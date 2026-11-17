"""A fake OpenID Connect identity provider for tests.

It answers the app's server-side calls (discovery, keys, token) through ``httpx2.MockTransport``, so no test
touches the network. ``sign_in`` plays the part of the browser at the provider's sign-in page.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

import httpx2
from joserfc import jwt
from joserfc.jwk import OctKey, RSAKey

CLIENT_ID = "accessdesk-test-client"
CLIENT_SECRET = "test-client-secret-0123456789abcdef"
ISSUER = "https://idp.example.test"


def _rsa(kid: str) -> RSAKey:
    return RSAKey.generate_key(2048, parameters={"kid": kid, "alg": "RS256", "use": "sig"}, private=True)


KEY = _rsa("key-1")
NEXT_KEY = _rsa("key-2")
STRANGER_KEY = _rsa("key-1")  # same key id as KEY but different key material: a forged signature

DROP = object()  # pass as a claim's value to leave the claim out of the ID token


def b64(data: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


def unsigned_token(claims: dict[str, Any]) -> str:
    return f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(claims)}."


def hmac_token(claims: dict[str, Any]) -> str:
    """Signed with the client secret, as some providers allow. AccessDesk only accepts public-key ones."""
    return jwt.encode({"alg": "HS256"}, claims, OctKey.import_key(CLIENT_SECRET))


class FakeProvider:
    def __init__(self, now: Callable[[], float], issuer: str = ISSUER) -> None:
        self.now = now
        self.issuer = issuer
        self.signing_key = KEY
        self.published = [KEY]
        self.auth_methods = ["client_secret_post", "client_secret_basic"]  # what discovery lists
        self.accepted_methods = {"client_secret_post", "client_secret_basic"}  # what the token endpoint takes
        self.discovery_changes: dict[str, Any] = {}
        self.down = False
        self.token_error: tuple[int, dict[str, Any]] | None = None
        self.forge: Callable[[dict[str, Any]], str] | None = None  # makes the next ID token instead
        self.codes: dict[str, dict[str, Any]] = {}
        self.token_requests: list[httpx2.Request] = []
        self.jwks_fetches = 0

    @property
    def transport(self) -> httpx2.MockTransport:
        return httpx2.MockTransport(self._handle)

    def discovery(self) -> dict[str, Any]:
        base = self.issuer.rstrip("/")
        return {
            "issuer": self.issuer,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "jwks_uri": f"{base}/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": self.auth_methods,
            "code_challenge_methods_supported": ["S256"],
            **self.discovery_changes,
        }

    # ----------------------------------------------------------------- the browser at the provider

    def sign_in(self, authorize_url: str, email: str = "alice@example.com", **claims: Any) -> str:
        """Check the sign-in request, 'sign the person in' and return the URL the provider redirects to."""
        url = urlsplit(authorize_url)
        assert f"{url.scheme}://{url.netloc}{url.path}" == self.discovery()["authorization_endpoint"]
        params = {key: values[0] for key, values in parse_qs(url.query).items()}
        assert params["response_type"] == "code"
        assert params["client_id"] == CLIENT_ID
        assert params["code_challenge_method"] == "S256"
        assert {"openid", "email"} <= set(params["scope"].split())
        code = secrets.token_urlsafe(16)
        self.codes[code] = {
            "challenge": params["code_challenge"],
            "redirect_uri": params["redirect_uri"],
            "claims": {"email": email, "email_verified": True, "nonce": params["nonce"], **claims},
        }
        return params["redirect_uri"] + "?" + urlencode({"code": code, "state": params["state"]})

    def claims(self, extra: dict[str, Any]) -> dict[str, Any]:
        now = int(self.now())
        claims = {
            "iss": self.issuer,
            "sub": f"subject-for-{extra.get('email')}",
            "aud": CLIENT_ID,
            "iat": now,
            "exp": now + 300,
            **extra,
        }
        return {key: value for key, value in claims.items() if value is not DROP}

    def sign(self, claims: dict[str, Any], key: RSAKey | None = None) -> str:
        key = key or self.signing_key
        return jwt.encode({"alg": "RS256", "kid": key.kid}, claims, key)

    # ----------------------------------------------------------------- server-side endpoints

    def _handle(self, request: httpx2.Request) -> httpx2.Response:
        if self.down:
            raise httpx2.ConnectError("the provider is down", request=request)
        path = request.url.path
        if request.method == "GET" and path.endswith("/.well-known/openid-configuration"):
            return httpx2.Response(200, json=self.discovery())
        if request.method == "GET" and path.endswith("/jwks"):
            self.jwks_fetches += 1
            return httpx2.Response(200, json={"keys": [k.as_dict(private=False) for k in self.published]})
        if request.method == "POST" and path.endswith("/token"):
            return self._token(request)
        return httpx2.Response(404, json={"error": "not_found"})

    def _token(self, request: httpx2.Request) -> httpx2.Response:
        self.token_requests.append(request)
        form = {key: values[0] for key, values in parse_qs(request.content.decode()).items()}
        client = (form.get("client_id"), form.get("client_secret"))
        method = "client_secret_post"
        authorization = request.headers.get("authorization", "")
        if authorization.startswith("Basic "):
            user, _, password = base64.b64decode(authorization[6:]).decode().partition(":")
            client = (unquote(user), unquote(password))
            method = "client_secret_basic"
        if client != (CLIENT_ID, CLIENT_SECRET) or method not in self.accepted_methods:
            return httpx2.Response(401, json={"error": "invalid_client"})
        if self.token_error is not None:
            return httpx2.Response(self.token_error[0], json=self.token_error[1])
        grant = self.codes.pop(form.get("code", ""), None)  # a code works once
        if grant is None or form.get("grant_type") != "authorization_code":
            return httpx2.Response(400, json={"error": "invalid_grant"})
        verifier = form.get("code_verifier", "")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        if challenge != grant["challenge"] or form.get("redirect_uri") != grant["redirect_uri"]:
            return httpx2.Response(400, json={"error": "invalid_grant"})
        claims = self.claims(grant["claims"])
        id_token = self.forge(claims) if self.forge else self.sign(claims)
        return httpx2.Response(
            200,
            json={"access_token": "opaque", "token_type": "Bearer", "expires_in": 3600, "id_token": id_token},
        )
