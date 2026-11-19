# MFEC Recording Explorer

Standalone MFEC-branded Genesys Cloud CX recording search application. It is separate from MFEC LeadSync and does not modify or deploy the referenced application.

## Current delivery

This project includes a React + TypeScript frontend, Express 5 backend, SQLite schema, server-side session authentication, role/access checks, same-origin and CSRF validation, login/API rate limiting, AES-256-GCM credential encryption, region allowlisting, OAuth Client Credentials, bounded Genesys conversation-detail queries, per-conversation recording discovery, authenticated media streaming/download proxy, audit events, password changes, user profile management, encrypted SMTP configuration, and explicit synthetic Mock Mode. The delivered single-instance target is Ubuntu with SQLite and one trusted Nginx TLS proxy. Multi-instance/PostgreSQL is not delivered.

Mock Mode shows three synthetic conversations (bot to agent, bot only, and multi-agent) with recording metadata. Synthetic recordings do not contain real audio. It is not a simulation of successful live playback.

## Requirements

- Node.js 20 or newer
- npm
- For live use: Genesys Cloud organization, OAuth client credentials with the minimum required permissions, and trusted HTTPS deployment

## Development setup

```sh
npm install
cp .env.example .env
```

Set a unique `SESSION_SECRET` (48+ characters for production), generate `MASTER_ENCRYPTION_KEY` as base64 for 32 random bytes, then set a local admin user/password. Example:

```sh
openssl rand -base64 32
```

Set `MOCK_MODE=true` to explore synthetic fixtures without Genesys credentials. Start the web and API processes:

```sh
npm run dev
```

Open <http://localhost:5173>. The initial administrator is created only when the database has no users and both `INITIAL_ADMIN_USERNAME` and `INITIAL_ADMIN_PASSWORD` are set. New passwords require at least eight characters, one letter (either case), and one number or special character; profile/password screens show live checks including confirmation. Production startup fails closed if no bootstrap account is supplied for an empty database; after creation the bootstrap password is removed from the process environment. Change the generated credential after first sign-in using **Settings → Change password**. Runtime SQLite files are written under `runtime/`.

Administrators manage account roles, profiles, password resets and organization grants under **Users & Access**. Users can update their own profile and password in **Settings**. SMTP uses **Settings → SMTP email delivery**; Gmail defaults are `smtp.gmail.com`, port 587 with STARTTLS. Enter the real Gmail account and its App Password (not the Gmail web-login password). SMTP secrets use the server's AES-256-GCM key and are never returned to the browser. A test-email action verifies the configured transport.

## Live Genesys setup

1. Set `MOCK_MODE=false` and restart the service. Production refuses to start with Mock Mode enabled; while Mock Mode is active, live connections cannot be created/tested/used.
2. Configure a Genesys OAuth Client Credentials integration for a dedicated least-privilege service account.
3. Grant the service identity only the permissions needed for analytics conversation detail and recording discovery/view/playback. Validate actual permissions against the target organization and applicable divisions.
4. Sign in as an application Administrator and add the named organization under **Genesys Configuration**. Select an allowlisted region; endpoint URLs are fixed to official regional API/OAuth hosts, preventing arbitrary endpoint SSRF or credential exfiltration.
5. Use **Test Connection** in the configuration dialog to verify OAuth and a Genesys organization API request (`GET /api/v2/organizations/me`). Draft credentials are tested server-side without saving them. This does not verify every analytics, division, recording, or media permission.
6. Run a short bounded search and confirm recordings through a controlled QA process.

Client Credentials use a service identity; they do **not** automatically inherit the logged-in app user's Genesys permissions. Application organization access and roles are additional restrictions, not delegated Genesys enforcement.

## Commands

```sh
npm run dev          # Vite + API
npm test             # Synthetic security/fixture tests
npm run build        # Production frontend and server build
npm start            # Start compiled production app
npm run db:migrate   # Apply idempotent SQLite schema
```

## Internal API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/health` | Health and execution mode |
| POST | `/api/auth/login` | Rate-limited username/password login |
| POST | `/api/auth/logout` | CSRF-protected logout |
| POST | `/api/auth/password` | Change own password and revoke existing sessions |
| GET | `/api/auth/me` | Current user and CSRF token |
| GET/PUT | `/api/user/profile` | Read/update the signed-in user's profile |
| GET/PUT | `/api/admin/users` | List/create users (administrator-only) |
| PUT | `/api/admin/users/:id/profile` | Administrator updates a user profile |
| POST | `/api/admin/users/:id/password` | Administrator resets a user's password and revokes their sessions |
| GET/PUT | `/api/admin/smtp` | Read safe SMTP status/save encrypted SMTP settings (administrator-only) |
| POST | `/api/admin/smtp/test` | Send an administrator-requested test email |
| GET | `/api/genesys/regions` | Trusted region catalogue |
| GET/POST | `/api/genesys/connections` | List/create connections (create is admin-only) |
| PUT/DELETE | `/api/genesys/connections/:id` | Admin connection change/removal |
| POST | `/api/genesys/connections/:id/test` | Test OAuth in live mode |
| POST | `/api/recordings/search` | Bounded details query + recording discovery |
| GET | `/api/recordings/conversations/:id` | Conversation detail |
| GET | `/api/recordings/conversations/:id/recordings` | Recording discovery |
| GET | `/api/recordings/:id/metadata` | Recording metadata |
| GET | `/api/recordings/:id/stream` | Authenticated media proxy (Range/no-store) |
| GET | `/api/recordings/:id/download` | Role-restricted audited download |
| GET | `/api/audit` | Administrator audit view |
| POST | `/api/audit/export` | Audit authorized result metadata export |
| GET | `/api/dashboard/summary` | Honest unavailable-metrics response until a full query is implemented |

All state-changing API calls except login require the session CSRF token in `x-csrf-token`. The login response and `/api/auth/me` provide the token. The app rejects non-matching `Origin` and cross-site Fetch Metadata requests. Authenticated sessions are revalidated against the current enabled account/role on each protected API request; role changes and account disablement revoke that user's existing sessions. There is no MFA/SSO integration in this delivery; configure a compensating perimeter identity control or explicitly accept this residual risk before production.

## Database and scaling

The SQLite schema is in `server/db/schema.sql`. It covers users, role column, organization access grants, connections, bot/flow registry, saved searches, preferences, customer mappings, optional conversation metadata index, audit logs, application settings, and sessions. Audio is never persisted. SQLite is for development/single instance; a multi-instance production install should migrate to PostgreSQL and a shared session store before scaling horizontally.

## Application versioning

The sidebar version is built from the root `package.json` version, so it is not maintained separately in the UI. Bump it once for each CR using the matching command before building/deploying:

| CR size | Command | Version change |
| --- | --- | --- |
| High Effort | `npm run version:high-effort` | `x + 1`, reset `y.z` to `0.0` |
| Small CR | `npm run version:small` | `y + 1`, reset `z` to `0` |
| UI/appearance-only CR | `npm run version:ui` | `z + 1` |

For example, from `1.8.6` these produce `2.0.0`, `1.9.0`, and `1.8.7`. Commit the updated `package.json` and `package-lock.json` with the CR; the client build automatically displays the resulting version.

## Deployment (Ubuntu, no Docker required)

1. Install Node.js 20+, create a dedicated `recording-explorer` service user, and deploy source to `/opt/mfec-recording-explorer`.
2. Run `npm ci`, configure `/etc/mfec-recording-explorer.env` with secrets and a runtime directory under `/var/lib/mfec-recording-explorer`, and ensure only the service user can read it (`root:recording-explorer`, mode `0640`; this is required because the app runs as the service group).
3. Set `NODE_ENV=production`, strong unique `SESSION_SECRET` (48+ characters), `MASTER_ENCRYPTION_KEY`, the public HTTPS `APP_ORIGIN`, `TRUST_PROXY=true` (only behind the one trusted Nginx proxy), `MOCK_MODE=false`, and a strong one-time initial admin password. Do not use example values. Startup rejects insecure/missing production configuration.
4. Run `npm run db:migrate`, `npm run build`, then start with the systemd unit below.
5. Terminate TLS at Nginx. Keep the Node listener loopback-only, use HTTPS/HSTS, restrict administrative access, firewall only required ports, and protect backups.

Example systemd unit (`/etc/systemd/system/mfec-recording-explorer.service`):

```ini
[Unit]
Description=MFEC Recording Explorer
After=network.target

[Service]
Type=simple
User=recording-explorer
Group=recording-explorer
WorkingDirectory=/opt/mfec-recording-explorer
EnvironmentFile=/etc/mfec-recording-explorer.env
Environment=DATABASE_PATH=/var/lib/mfec-recording-explorer/app.sqlite
Environment=HOST=127.0.0.1
ExecStart=/usr/bin/node /opt/mfec-recording-explorer/dist-server/server/index.js
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mfec-recording-explorer
UMask=0077

[Install]
WantedBy=multi-user.target
```

Apply restrictive environment-file permissions for this unit's service-group access:

```sh
chown root:recording-explorer /etc/mfec-recording-explorer.env
chmod 0640 /etc/mfec-recording-explorer.env
```

Example Nginx reverse proxy:

```nginx
server {
  listen 443 ssl http2;
  server_name recordings.example.com;
  ssl_certificate /etc/letsencrypt/live/recordings.example.com/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/recordings.example.com/privkey.pem;
  add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
  client_max_body_size 256k;
  location / {
    proxy_pass http://127.0.0.1:4178;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_read_timeout 3600s;
    proxy_buffering off;
  }
}
```

When behind a TLS proxy, this single-instance deployment supports exactly one trusted Nginx proxy (`TRUST_PROXY=true`). Keep the app bound to loopback and do not expose the backend listener publicly. Review the IP-forwarding/proxy chain if deployment topology differs.

### Backup and restore

Stop the service or use SQLite's online backup mechanism to produce a consistent database copy. Encrypt backups at rest, restrict access to the service/security team, and include the master encryption key separately in the organization's secrets escrow (without it stored integration secrets cannot be recovered). Define and test retention/deletion policies. Do not back up streamed audio because the app does not store it.

## Search semantics and known limitations

- Genesys analytics requests are limited to a seven-day interval here to stay within the documented no-filter detail-query maximum. Filtered-query limits and asynchronous jobs should be validated for the target data volume; large-range async details jobs are not yet implemented.
- User/queue/direction filters are sent to Analytics where supported. Agent/queue IDs currently require IDs; reference-data APIs are not yet implemented.
- ANI/DNIS in native Genesys mode are post-filtered only on the current result page and are clearly marked incomplete. Do not use them as a complete customer-phone search.
- Recording availability is verified per returned conversation by calling the conversation recordings endpoint. A successful conversation query does not imply an available recording.
- Participant purpose and returned flow fields are used as classification signals. Names alone are not sufficient for bot classification; admin-managed flow mapping is schema-ready but not yet surfaced.
- The browser audio player uses an authenticated backend stream proxy and HTTP Range forwarding. Media URL structure/host allowlists and redirects are validated, and no redirects are followed to untrusted hosts. Actual Genesys recording response/media URI variants still require validation against an authorized non-production organization. Signed media URLs are not persisted/logged.
- ANI/DNIS remain post-filtered on a fetched API page; this can miss matching conversations outside that page. A conversation-ID lookup now checks the selected supported filters but does not use Analytics paging.
- Dashboard metrics and Speech and Text Analytics transcripts are available in bounded form. Dashboard queries are limited to 30 days, split into seven-day requests, capped at 1,000 conversations, and explicitly labeled partial when limits or recording permissions prevent complete totals. Transcript URLs are retrieved and validated server-side; neither OAuth credentials nor signed transcript URLs are sent to the browser.
- Customer enrichment/indexing, filter capability registry and nested AND/OR groups, server-persisted saved searches, reference-data pickers, division-aware app grants, asynchronous details jobs, playback-history UI, audit retention/archival jobs, and multi-instance/PostgreSQL support are not delivered. Advanced UI-only fields are informational/disabled in function, not server-side search criteria; do not rely on them.
- No live Genesys organization was available here; live OAuth, search, recording, transcription, CORS/media, permissions and formats are unverified.

## Production security checklist

- [ ] HTTPS only, secure cookies, TLS termination and HSTS verified
- [ ] Replace all sample secrets; restrict environment file to root/service group; backups encrypted
- [ ] `MOCK_MODE=false` only for an authorized organization; least-privilege OAuth integration
- [ ] Validate service-account divisions, recording permissions, and retention controls with Genesys admins
- [ ] Set trusted proxy configuration narrowly; restrict inbound network exposure
- [ ] Change the bootstrap admin password; establish operational account lifecycle and MFA/SSO perimeter policy (not provided by this app)
- [ ] Audit retention, source IP privacy policy, access-review process and incident response approved
- [ ] Test recording access denial, downloads, Range playback, expired media URLs and deletion against non-production data
- [ ] Review dependency advisory output and update lockfile/dependencies before deployment
- [ ] Configure tested SQLite backups for single-instance deployment; use PostgreSQL/shared sessions for multiple instances

## Reference and API behavior

The visual layout takes inspiration from the public MFEC LeadSync source's navy grouped sidebar, white top bar, blue actions, light workspace, typography, and theme switching. No LeadSync source was copied into or modified by this project. Genesys API behavior referenced: official Developer Center Conversation Detail Query docs (paging and interval constraints), Conversations API reference, official recording downloader guide, and Genesys Cloud API regional domains. Confirm request schema, response media URI format, permissions, retention and region endpoints with current official API Explorer/specifications during live deployment.
