"""Single sign-on with OpenID Connect: the authorization code flow with PKCE, state and nonce.

1. ``start()`` makes a random state, nonce and PKCE verifier, and the provider's sign-in address. The web
   layer keeps the three values in the person's signed session cookie.
2. The provider sends the browser back with ``code`` and ``state``. The web layer checks the state.
3. ``finish()`` swaps the code and the PKCE verifier for tokens at the provider's token endpoint, then
   checks the ID token: its signature (against the provider's published keys), issuer, audience, expiry,
   issue time and nonce. Last, it insists on a verified email address from an allowed domain.

Signatures and claims are checked with joserfc. Only asymmetric algorithms are accepted, so a token can
never be "signed" with ``none`` or with a shared secret. The provider's settings and keys are cached, and
the keys are fetched again when a token names a key we have not seen, so key rotation just works.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

import httpx2
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

from accessdesk import __version__
from accessdesk.config import OidcSettings, is_secure_url

ASYMMETRIC_ALGORITHMS = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
)
SCOPES = "openid email profile"
LEEWAY_SECONDS = 60  # clock difference allowed between this server and the provider
CACHE_SECONDS = 3600  # how long the provider's settings and keys are reused
KEY_REFETCH_SECONDS = 60  # an unknown key id never makes us fetch keys more often than this
TIMEOUT_SECONDS = 10.0


class SignInError(Exception):
    """Sign-in failed. ``reason`` is a short code for logs and metrics. Nothing here is ever secret."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


class ProviderUnavailable(SignInError):
    """The identity provider could not be reached or answered with something unusable."""


class EmailNotVerified(SignInError):
    """The ID token has no email address, or the provider does not vouch for it."""

    def __init__(self, reason: str, email: str = "") -> None:
        super().__init__(reason)
        self.email = email


class EmailDomainNotAllowed(SignInError):
    def __init__(self, email: str) -> None:
        super().__init__("domain_not_allowed")
        self.email = email


@dataclass(frozen=True, slots=True)
class Provider:
    """The parts of the provider's discovery document that sign-in uses."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    algorithms: tuple[str, ...]
    client_auth: str  # client_secret_post or client_secret_basic


@dataclass(frozen=True, slots=True)
class LoginRequest:
    url: str
    state: str
    nonce: str
    verifier: str


@dataclass(frozen=True, slots=True)
class VerifiedIdentity:
    email: str  # lower case
    subject: str


def pkce_challenge(verifier: str) -> str:
    """The S256 code challenge for a PKCE verifier (RFC 7636)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _says_true(value: object) -> bool:
    """True only for a clear yes. Some providers send booleans as strings or numbers."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value == 1
    return isinstance(value, str) and value.strip().lower() in {"true", "1"}


def safe_code(value: object) -> str:
    """A provider error code, made safe to log: letters, digits and underscores only, kept short."""
    return re.sub(r"[^A-Za-z0-9_]", "", str(value))[:40] if value else ""


class OidcClient:
    def __init__(
        self,
        settings: OidcSettings,
        redirect_uri: str,
        *,
        transport: httpx2.AsyncBaseTransport | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.settings = settings
        self.redirect_uri = redirect_uri
        self._transport = transport  # tests swap in a fake identity provider here
        self._now = now
        self._provider: Provider | None = None
        self._provider_at = 0.0
        self._keys: KeySet | None = None
        self._keys_at = 0.0

    # ----------------------------------------------------------------- the two steps

    async def start(self) -> LoginRequest:
        provider = await self.provider()
        state, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(48)
        params = {
            "response_type": "code",
            "client_id": self.settings.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": SCOPES,
            "state": state,
            "nonce": nonce,
            "code_challenge": pkce_challenge(verifier),
            "code_challenge_method": "S256",
        }
        if self.settings.is_google and len(self.settings.allowed_domains) == 1:
            params["hd"] = self.settings.allowed_domains[0]  # Google shows only accounts from this domain
        joiner = "&" if "?" in provider.authorization_endpoint else "?"
        return LoginRequest(
            provider.authorization_endpoint + joiner + urlencode(params), state, nonce, verifier
        )

    async def finish(self, code: str, verifier: str, nonce: str) -> VerifiedIdentity:
        provider = await self.provider()
        id_token = await self._exchange(provider, code, verifier)
        claims = await self._verify(provider, id_token, nonce)
        return self._identity(claims)

    # ----------------------------------------------------------------- provider settings and keys

    async def provider(self) -> Provider:
        if self._provider is None or self._now() - self._provider_at > CACHE_SECONDS:
            url = self.settings.issuer.rstrip("/") + "/.well-known/openid-configuration"
            self._provider = self._parse_discovery(await self._get_json(url))
            self._provider_at = self._now()
        return self._provider

    def _parse_discovery(self, data: dict[str, Any]) -> Provider:
        issuer = data.get("issuer")
        # OpenID Connect Discovery 1.0, section 4.3: the document must name the issuer we asked.
        if not isinstance(issuer, str) or issuer.rstrip("/") != self.settings.issuer.rstrip("/"):
            raise ProviderUnavailable("issuer_mismatch", f"the provider calls itself {issuer!r}")
        endpoints: dict[str, str] = {}
        for name in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            value = data.get(name)
            if not isinstance(value, str) or not is_secure_url(value.split("?", 1)[0]):
                raise ProviderUnavailable("bad_discovery", f"{name} is missing or not https")
            endpoints[name] = value
        offered = data.get("id_token_signing_alg_values_supported")
        algorithms = (
            tuple(a for a in offered if a in ASYMMETRIC_ALGORITHMS) if isinstance(offered, list) else ()
        )
        methods = data.get("token_endpoint_auth_methods_supported")
        client_auth = (
            "client_secret_post"
            if isinstance(methods, list) and "client_secret_post" in methods
            else "client_secret_basic"  # the default in OAuth 2.0
        )
        return Provider(
            issuer=issuer,
            authorization_endpoint=endpoints["authorization_endpoint"],
            token_endpoint=endpoints["token_endpoint"],
            jwks_uri=endpoints["jwks_uri"],
            algorithms=algorithms or ("RS256",),
            client_auth=client_auth,
        )

    async def _key_set(self, provider: Provider, *, refresh: bool = False) -> KeySet:
        age = self._now() - self._keys_at
        if refresh and age < KEY_REFETCH_SECONDS:
            raise SignInError("unknown_signing_key")
        if self._keys is None or refresh or age > CACHE_SECONDS:
            data = await self._get_json(provider.jwks_uri)
            try:
                keys = KeySet.import_key_set(data)  # type: ignore[arg-type]
            except (JoseError, KeyError, TypeError, ValueError):
                raise ProviderUnavailable("bad_jwks", "the provider's keys could not be read") from None
            self._keys, self._keys_at = keys, self._now()
        return self._keys

    # ----------------------------------------------------------------- tokens

    async def _exchange(self, provider: Provider, code: str, verifier: str) -> str:
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": verifier,
        }
        auth: httpx2.Auth | None = None
        if provider.client_auth == "client_secret_post":
            form |= {"client_id": self.settings.client_id, "client_secret": self.settings.client_secret}
        else:
            # RFC 6749, section 2.3.1: form-encode both parts before Basic authentication.
            auth = httpx2.BasicAuth(
                quote(self.settings.client_id, safe=""), quote(self.settings.client_secret, safe="")
            )
        try:
            async with self._client(auth) as client:
                response = await client.post(provider.token_endpoint, data=form)
        except httpx2.HTTPError as exc:
            raise ProviderUnavailable("token_endpoint_unreachable", type(exc).__name__) from None
        if response.status_code >= 500:
            raise ProviderUnavailable("token_endpoint_error", str(response.status_code))
        try:
            body = response.json()
        except ValueError:
            body = None
        if response.status_code != 200 or not isinstance(body, dict):
            error = body.get("error") if isinstance(body, dict) else ""
            raise SignInError("token_refused", f"{response.status_code} {safe_code(error)}".strip())
        id_token = body.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise SignInError("no_id_token")
        return id_token

    async def _verify(self, provider: Provider, id_token: str, nonce: str) -> dict[str, Any]:
        registry = JWSRegistry(algorithms=provider.algorithms, strict_check_header=False)
        try:
            try:
                token = jwt.decode(id_token, await self._key_set(provider), registry=registry)
            except InvalidKeyIdError:
                # The provider may have rotated its keys since we last fetched them.
                token = jwt.decode(id_token, await self._key_set(provider, refresh=True), registry=registry)
        except (JoseError, ValueError) as exc:
            raise SignInError("bad_id_token", type(exc).__name__) from None

        claims: dict[str, Any] = token.claims
        issuers = [provider.issuer]
        if self.settings.is_google:
            issuers.append("accounts.google.com")  # Google documents both forms
        checks = jwt.JWTClaimsRegistry(
            now=int(self._now()),
            leeway=LEEWAY_SECONDS,
            iss={"essential": True, "values": issuers},
            sub={"essential": True},
            aud={"essential": True},
            exp={"essential": True},
            iat={"essential": True},
        )
        try:
            checks.validate(claims)
        except JoseError as exc:
            raise SignInError("bad_id_token", type(exc).__name__) from None

        # The token must be for this app alone (OpenID Connect Core 1.0, section 3.1.3.7).
        client_id = self.settings.client_id
        audiences = [claims["aud"]] if isinstance(claims["aud"], str) else list(claims["aud"])
        if set(audiences) != {client_id}:
            raise SignInError("wrong_audience")
        if claims.get("azp", client_id) != client_id:
            raise SignInError("wrong_authorized_party")
        sent = claims.get("nonce")
        if not isinstance(sent, str) or not hmac.compare_digest(sent.encode(), nonce.encode()):
            raise SignInError("nonce_mismatch")
        return claims

    def _identity(self, claims: dict[str, Any]) -> VerifiedIdentity:
        raw = claims.get("email")
        if not isinstance(raw, str) or "@" not in raw:
            raise EmailNotVerified("no_email")
        email = raw.strip().lower()
        # Microsoft Entra ID does not send email_verified; its xms_edov claim says the domain is verified.
        if not (_says_true(claims.get("email_verified")) or _says_true(claims.get("xms_edov"))):
            raise EmailNotVerified("email_not_verified", email)
        allowed = self.settings.allowed_domains
        if allowed:
            if email.rsplit("@", 1)[1] not in allowed:
                raise EmailDomainNotAllowed(email)
            # A personal Google account can carry a work address. Only Workspace accounts have "hd".
            if self.settings.is_google and str(claims.get("hd", "")).lower() not in allowed:
                raise EmailDomainNotAllowed(email)
        return VerifiedIdentity(email=email, subject=str(claims["sub"]))

    # ----------------------------------------------------------------- HTTP

    def _client(self, auth: httpx2.Auth | None = None) -> httpx2.AsyncClient:
        return httpx2.AsyncClient(
            auth=auth,
            transport=self._transport,
            timeout=TIMEOUT_SECONDS,
            headers={"User-Agent": f"AccessDesk/{__version__}", "Accept": "application/json"},
        )

    async def _get_json(self, url: str) -> dict[str, Any]:
        try:
            async with self._client() as client:
                response = await client.get(url)
            response.raise_for_status()
            data = response.json()
        except (httpx2.HTTPError, ValueError) as exc:
            raise ProviderUnavailable("provider_unreachable", f"{type(exc).__name__} from {url}") from None
        if not isinstance(data, dict):
            raise ProviderUnavailable("bad_response", url)
        return data
