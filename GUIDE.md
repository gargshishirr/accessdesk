# AccessDesk guide

How to use AccessDesk, run it and look after it. For the design, tests and benchmarks, see the
[README](README.md).

## What it is

AccessDesk lets people ask for temporary access to company systems. The right people approve it, the access
ends on its own, and every step is written to a tamper-evident audit log.

Other systems can ask AccessDesk "does this person have this access right now?" through a small API.

## Features

- **Company sign-in.** Single sign-on with Google Workspace, Microsoft Entra ID, Okta, Auth0, Keycloak or any
  other OpenID Connect provider.
- **The right approvers.** Who approves depends on how sensitive the system is: the manager, the owner, the
  security team, or a mix. Nobody approves their own request.
- **Access that ends.** Every grant has an end time. People can give access back early, and owners or
  security can remove it with a reason.
- **Safety rules.** Separation-of-duties rules stop one person holding two risky kinds of access at once.
- **Audit log.** Every change is recorded in a SHA-256 hash chain, so any edit to the history shows up.
- **A directory you control.** One JSON file lists people, managers, systems and owners. When someone
  leaves, their access ends at once.
- **An API for other services**, with keys you can rotate without downtime.
- **Accessible.** Works with a keyboard, screen readers, zoom and high contrast, with no JavaScript.

## How to use

### Signing in

Select **Sign in with your company account**. You sign in on your company's usual page and come straight
back to AccessDesk.

In **demo mode** a yellow banner says "anyone can sign in as anyone", and you pick a person from a list.
Demo mode is only for trying AccessDesk, never for real data.

### Asking for access (everyone)

1. Select **Request access** and choose a system.
2. Choose the lowest level that does the job and the number of hours, and say why you need it.
3. Select **Send request**. The next page shows who needs to approve it.

Low-risk read access for some teams is granted at once. **My access** shows what you have and when it ends.
Select **Give back now** if you finish early.

### Approving requests (managers and owners)

**Approvals** lists the requests waiting for you. Open one, choose **Approve** or **Deny** and add a comment
(a comment is needed to deny). Access starts when every approver has said yes.

### Reviewing access (owners and the security team)

**Access reviews** shows who has access to the systems you own (everything, for the security team). Select
**Remove** to end someone's access early. Your reason goes in the audit log, and they see it too.

### The audit log (security team)

**Audit log** shows the latest changes and checks the whole hash chain every time it opens. "Chain intact"
means nothing in the history was changed.

### Other services (the API)

Services send an API key in the `X-API-Key` header:

```bash
curl -H "X-API-Key: $ACCESSDESK_KEY" \
  "https://access.example.com/api/v1/check?user=alice&resource=prod-db&role=viewer"
```

The answer has `"allowed": true` only while an unexpired grant covers that role. `GET /api/v1/audit/verify`
reports on the audit chain, and `/api/openapi.json` describes the whole API.

## How to maintain

### Settings

AccessDesk reads its settings from environment variables. Without the single sign-on settings it runs in
demo mode.

| Setting | What it does |
|---|---|
| `ACCESSDESK_DB` | Where the database file lives. Default: `accessdesk.db`. |
| `ACCESSDESK_PUBLIC_URL` | The address people use, like `https://access.example.com`. Needed for single sign-on. On Render it is filled in for you. |
| `ACCESSDESK_SECRET_KEY` | Signs the session cookie. Needed for single sign-on (at least 32 characters). |
| `ACCESSDESK_OIDC_ISSUER`, `ACCESSDESK_OIDC_CLIENT_ID`, `ACCESSDESK_OIDC_CLIENT_SECRET` | Turn on single sign-on. |
| `ACCESSDESK_OIDC_ALLOWED_DOMAINS` | Email domains that may sign in, comma-separated. Needed for Google. |
| `ACCESSDESK_API_KEYS` | API keys, comma-separated, at least 32 characters each. With single sign-on and no key, the API is off. |
| `ACCESSDESK_DIRECTORY_FILE` | A directory file to load every time AccessDesk starts. |
| `ACCESSDESK_SESSION_HOURS` | How long a sign-in lasts. Default: 24. |
| `ACCESSDESK_SIGNIN_RATE_LIMIT` | Sign-ins started per minute from one address. Default: 30. `0` turns it off. |
| `ACCESSDESK_API_RATE_LIMIT` | API calls per minute for one key. Default: 6000. `0` turns it off. |
| `ACCESSDESK_CLIENT_IP_HEADER` | Behind a proxy, the header that holds each visitor's address, so rate limits count visitors separately. Render's blueprint sets `CF-Connecting-IP`. |

To make a random key:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

AccessDesk refuses to start if the settings cannot work, and says which one to fix. It never falls back to
demo mode by itself. The README lists two more settings for special cases.

### Run it on Render

The **Deploy to Render** button in the README creates a free demo. For real use, open the service in the
Render dashboard and:

1. Under **Settings**, pick a paid instance type. Under **Disk**, add a disk mounted at `/var/data`.
2. Under **Environment**, set `ACCESSDESK_DB` to `/var/data/accessdesk.db`, and add the single sign-on
   settings (see below).
3. Under **Environment → Secret Files**, add your directory as `directory.json`, and set
   `ACCESSDESK_DIRECTORY_FILE` to `/etc/secrets/directory.json`.

Each time you save the secret file, Render redeploys and AccessDesk loads the new directory. If you use your
own domain, also set `ACCESSDESK_PUBLIC_URL` to it.

### Run it on your own server

With Docker, from a copy of this repository:

```bash
docker build -t accessdesk .
docker run -d --name accessdesk --restart unless-stopped -p 127.0.0.1:8000:8000 \
  -v accessdesk-data:/data --env-file accessdesk.env accessdesk
```

`accessdesk.env` holds your settings, one `NAME=value` per line. Keep it private and out of Git.

Put an HTTPS proxy in front, for example [Caddy](https://caddyserver.com):
`caddy reverse-proxy --from access.example.com --to 127.0.0.1:8000`. Then add
`ACCESSDESK_CLIENT_IP_HEADER=X-Forwarded-For` to `accessdesk.env`, so AccessDesk sees each visitor's address.

Without Docker, run `pip install .` and then `accessdesk serve` (it listens on 127.0.0.1:8000) behind the
same proxy.

### Set up single sign-on

Register AccessDesk with your identity provider as a web app, with this redirect URI:
`https://<your address>/auth/callback`. AccessDesk prints the exact URI when it starts.

**Google Workspace**

1. In the [Google Cloud console](https://console.cloud.google.com), open **Google Auth Platform**. Under
   **Audience**, choose **Internal**.
2. Under **Clients**, select **Create client**, choose **Web application** and add the redirect URI.
3. Copy the client ID and client secret (Google shows the secret only once), then set:

```text
ACCESSDESK_OIDC_ISSUER=https://accounts.google.com
ACCESSDESK_OIDC_CLIENT_ID=<client ID>
ACCESSDESK_OIDC_CLIENT_SECRET=<client secret>
ACCESSDESK_OIDC_ALLOWED_DOMAINS=<your Workspace domain, like example.com>
```

**Microsoft Entra ID**

1. In the [Microsoft Entra admin center](https://entra.microsoft.com), go to **App registrations → New
   registration**. Choose **Accounts in this organizational directory only** and add a **Web** redirect URI.
2. Copy the **Application (client) ID** and the **Directory (tenant) ID**. Under **Certificates & secrets**,
   create a client secret and copy its **Value**.
3. Under **Manifest**, set `"optionalClaims"` to the value below and save. Entra does not send
   `email_verified`; `xms_edov` tells AccessDesk the email's domain is verified.

```json
"optionalClaims": {
  "idToken": [{"name": "email", "essential": false}, {"name": "xms_edov", "essential": false}]
}
```

4. Under **API permissions**, make sure Microsoft Graph **email**, **openid** and **profile** are listed,
   then select **Grant admin consent**. Then set:

```text
ACCESSDESK_OIDC_ISSUER=https://login.microsoftonline.com/<tenant ID>/v2.0
ACCESSDESK_OIDC_CLIENT_ID=<application ID>
ACCESSDESK_OIDC_CLIENT_SECRET=<secret value>
ACCESSDESK_OIDC_ALLOWED_DOMAINS=<your email domain, like example.com>
```

**Okta, Auth0, Keycloak and others**

Create an OpenID Connect web application that uses the authorization code flow, and add the redirect URI.
The issuer is the address in front of `/.well-known/openid-configuration`, for example
`https://example.okta.com`, `https://example.eu.auth0.com/` or `https://sso.example.com/realms/staff`.

### Load the directory

The directory lists everyone who can sign in, their managers, the systems people can ask for and their
owners. The easiest start is to export the current one and edit it:

```bash
accessdesk directory export directory.json
```

Each person needs an `id`, a `name` and an `email`. `manager` is another person's `id`, and
`"security": true` puts someone in the security team. Each system ("resource") needs an `id`, a `name`, an
`owner`, a `sensitivity` (`low`, `medium`, `high` or `critical`), `max_hours` and `roles`.

```json
{
  "people": [
    {"id": "alice", "name": "Alice Chen", "email": "alice@example.com", "team": "payments", "manager": "bob"},
    {"id": "bob", "name": "Bob Singh", "email": "bob@example.com", "team": "payments"},
    {"id": "dan", "name": "Dan Okafor", "email": "dan@example.com", "team": "security", "security": true}
  ],
  "resources": [
    {"id": "prod-db", "name": "Production Database", "owner": "bob", "sensitivity": "high",
     "max_hours": 24, "roles": ["viewer", "editor"]}
  ]
}
```

Check what would change, then load it:

```bash
accessdesk directory import directory.json --dry-run
accessdesk directory import directory.json
```

When someone leaves, set `"active": false` for them and load the file again. Their sessions, access and
pending requests end at once, and they stay in the history. If a change leaves a waiting request with a step
nobody can approve (say its approver left), that step goes to the security team.

Retire a system the same way, with `"active": false`.

People and systems missing from the file are left as they are. A file with a mistake changes nothing and
lists every problem, and every change goes in the audit log. Optional fields: `title`, `team`,
`description`, `auto_approve_teams` (teams that get low-risk viewer access at once) and
`separation_of_duties` (see an export for the format).

### Back up the database

```bash
mkdir -p backups
accessdesk backup backups/accessdesk-$(date +%F).db
```

This is safe while AccessDesk runs, and only your user can read the copy. With Docker, run
`docker exec accessdesk accessdesk backup /data/backup.db`, then `docker cp accessdesk:/data/backup.db .`.

To restore, stop AccessDesk, delete any `-wal` and `-shm` files next to the database, and copy the backup
over the database file. Render also snapshots its disks every day.

### Check the audit log

```bash
accessdesk verify-audit
```

It prints `OK` with the newest hash, or `BROKEN at entry N` and exits with code 1. Keeping a copy of the
newest hash somewhere else also catches anyone deleting the latest entries.

### Rotate keys

- **API keys:** set `ACCESSDESK_API_KEYS` to `new-key,old-key`, move each service to the new key, then remove
  the old one.
- **Session secret:** change `ACCESSDESK_SECRET_KEY` and restart. Everyone has to sign in again once.
- **Single sign-on secret:** create a new client secret at your provider, update
  `ACCESSDESK_OIDC_CLIENT_SECRET`, restart, then delete the old secret. Entra secrets expire, so note the date.

### Monitor it

`GET /healthz` answers `{"status": "ok"}` when AccessDesk and its database work. Prometheus can read
`/metrics` with an API key as a bearer token (`authorization: {credentials: <API key>}` in the scrape
config).

### Update

```bash
git pull
pip install .
```

Then restart AccessDesk; it upgrades the database by itself. With Docker, build the image again and start a
new container with the same volume. On Render, pushing to the repository redeploys.

CI runs every test on each change, and a dependency audit (`pip-audit`) every week.

## Security & privacy

- Sign-in uses OpenID Connect with PKCE, state and nonce. AccessDesk checks the ID token's signature,
  issuer, audience and expiry, and the email address must be verified.
- Only people in the directory can sign in. Signing in never creates a person or gives anyone a role.
- Sessions are stored on the server. Signing out, leaving the directory or 24 hours ends them. Cookies are
  `HttpOnly`, `SameSite=Lax` and, over HTTPS, `Secure` with the `__Host-` prefix.
- Every form has a CSRF token, every page has a strict Content Security Policy with no scripts, and sign-in
  only ever returns you to a page on the same site.
- Sign-in and the API have rate limits. API keys are compared in constant time.
- AccessDesk stores names, work email addresses, teams, managers, requests with their reasons, and the audit
  log. It stores no passwords and no tokens from your provider.
- Logs hold no secrets, no sign-in codes and no email addresses of refused sign-ins.
- A database that has been used with single sign-on never opens in demo mode.

## Troubleshooting

| Problem | What to do |
|---|---|
| "AccessDesk cannot start: ..." | The message names the setting to fix. |
| The provider says the redirect URI does not match | Register exactly the URI that AccessDesk prints when it starts. |
| "You are not in AccessDesk's directory" | Add the person, with that exact email, to the directory file and load it. |
| "Your email address could not be confirmed" | Entra: add the `xms_edov` claim (see above). Keycloak: tick **Email verified** for the user. |
| "Use your work account" | The email's domain is not in `ACCESSDESK_OIDC_ALLOWED_DOMAINS`. With Google, the account must belong to your Workspace. |
| "Single sign-on is not available right now" | AccessDesk could not reach the provider. Check `ACCESSDESK_OIDC_ISSUER` and the server's internet access. |
| "Too many sign-in attempts" | Wait a minute. Behind a proxy, set `ACCESSDESK_CLIENT_IP_HEADER` (see the settings). If many people share one office address, raise `ACCESSDESK_SIGNIN_RATE_LIMIT`. |
| "This page has expired" | Refresh the page and try again. Forms only work in the session they were opened in. |
| The API answers 401 | Send a current key in `X-API-Key`. With single sign-on, the API stays off until `ACCESSDESK_API_KEYS` is set. |
| The API answers 429 | That key used up its per-minute limit, or that address sent too many wrong keys. Wait a minute. |
| `verify-audit` says `BROKEN` | Someone changed the database directly. Restore a backup and find out who. |
