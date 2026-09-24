# N2 License Server

Multi-product, hardened license + update server for ThaliaNET and other desktop applications.

## Features

- Ed25519-signed, product-bound license leases with offline grace, revocation, and lock orders.
- Cryptographically random license keys with checksum and configurable activation limits.
- Admin product catalogue; each key belongs to exactly one product.
- Admin dashboard with keys, installations, heartbeats, releases, users, and audit log.
- Server-side pagination, filtering, and allow-listed ordering on admin tables.
- Soft delete and restore; no hard-delete admin actions.
- Hardware-bound installations and signed product-mismatch rejection.
- Bcrypt authentication, TOTP 2FA, CSRF protection, secure cookies, rate limiting, and lockout.
- Docker readiness health check for automatic Coolify recovery.
- Docker + Coolify ready.

## Quick start (local)

```bash
cp env.example .env
# edit .env and set ADMIN_PASSWORD_HASH and SECRET_KEY

# Generate password hash
python init_admin.py

# Run locally
pip install -r requirements.txt
python -m app.main
```

Open http://localhost:8000/admin.

## Docker (local)

```bash
cp env.example .env
# Create .env first (see env.example)
docker compose -f docker-compose.local.yml up -d
```

## Coolify deployment on n2.systems

Your Hetzner server (`46.4.65.32`) already runs Coolify and owns ports `80`/`443`. The license server must be deployed **behind Coolify's proxy**, not by publishing host ports.

### 1. Repository

This repository is the application root. Push changes to GitHub and deploy this repo directly in Coolify (no base directory needed). The repository is public so Coolify can pull it without extra GitHub App permissions.

```bash
git add .
git commit -m "N2 License Server update"
git push
```

### 2. Create the application in Coolify

1. Open your Coolify dashboard.
2. **Add a new Resource** → **Application**.
3. Choose **Public Repository** and select `greemlin/n2-license-server`.
4. Set **Build Pack** to `Dockerfile`.
5. Expose port `8000` (Coolify will route its proxy to this internal port).
6. Add your domain, for example:
   - `license.n2.systems`
7. Enable **HTTPS** / **Let's Encrypt**.
8. Add a **Persistent Volume** mounted at `/app/data` so the SQLite DB and Ed25519 keys survive redeploys.

### 3. Environment variables

Copy the values from `env.example` into Coolify's environment tab.

| Variable | Required | Example / note |
|---|---|---|
| `ADMIN_USERNAME` | yes | `admin` |
| `ADMIN_PASSWORD_HASH` | yes | bcrypt hash from `python init_admin.py` |
| `SECRET_KEY` | yes | 32+ byte random string |
| `DATABASE_URL` | yes | `sqlite:///./data/license_server.db` |
| `DEFAULT_OFFLINE_GRACE_DAYS` | yes | `10` |
| `DEFAULT_ACTIVATION_LIMIT` | yes | `1` |
| `DEBUG` | yes | `false` (so cookies are `Secure`) |
| `SENTRY_DSN` | no | only if you want server-side error tracking |

### 4. DNS

Add an **A record** for `license.n2.systems` pointing to `46.4.65.32`. Keep it DNS-only (grey cloud) in Cloudflare so Let's Encrypt HTTP-01 validation succeeds.

### 5. Deploy

Click **Deploy** in Coolify. The app builds from the Dockerfile, starts on internal port `8000`, and is reachable at `https://license.n2.systems`.

Verify liveness and readiness:

```bash
curl https://license.n2.systems/admin/health
# expected: {"status":"ok"}

curl https://license.n2.systems/admin/ready
# expected: {"status":"ready"}
```

The readiness check verifies database access and persistent Ed25519 signing keys.
Coolify/Docker uses the image health check to restart unhealthy containers.
A temporary server outage does not immediately stop applications: clients use
their already-valid signed offline lease until its configured deadline.

### 6. First-run setup

1. Open `https://license.n2.systems/admin`.
2. Log in with the username + password from step 3.
3. Enable TOTP 2FA for the owner account under **Admin Users**.
4. Create products under **Products** before issuing their keys.
5. Create a key from **License Keys** and select its product, edition, expiration,
   offline grace period, and activation limit.
6. The Ed25519 key pair is generated automatically on first start and stored in
   `/app/data/keys`. Because `/app/data` is persistent, the same keys survive redeploys.

### 7. Configure ThaliaMed

In the desktop app's production config, point it to:

```toml
[license]
server_url = "https://license.n2.systems"
```

The app will call:

- `POST https://license.n2.systems/api/license/sync`
- `POST https://license.n2.systems/api/license/ack`

## Smoke test

```bash
python _smoke_full.py
```

This exercises the full flow: admin login, key creation, client sync/activation, admin lock/unlock, ack, and revocation.

## Admin API / client endpoints

| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/license/sync` | Desktop app checks in, receives signed lease |
| POST | `/api/license/ack` | Confirm delivery of lock/unlock orders |
| POST | `/api/license/heartbeat` | Heartbeat from a known installation |
| GET  | `/api/updates/check` | Check for available update |

## Security notes

- Keep `data/keys/private.pem` secret and backed up. Loss of this key prevents
  future signing; replacement requires a controlled client public-key rotation.
- Rotate `SECRET_KEY`, admin password, GitHub tokens, Coolify tokens, and Cloudflare
  tokens before production if they were exposed during setup.
- Enable TOTP for every owner account.
- Admin state-changing forms require CSRF tokens; do not disable this protection.
- Viewer accounts are read-only. Restrict owner/admin accounts to trusted staff.
- Product identity is part of the signed license response; clients must verify it.
- Run behind HTTPS; set secure cookies in production (`DEBUG=false`).
- Do **not** publish host port `8000`; let Coolify route internally.
- Back up the persistent `/app/data` volume and regularly test restoration.
- The offline lease preserves application continuity during temporary server outage;
  it must not be treated as a way to bypass expiry, revocation, locking, or hardware binding.

## Backups

Persist `data/license_server.db` and `data/keys/private.pem`.
