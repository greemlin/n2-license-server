# N2 License Server

Production-ready license + update server for ThaliaMed / N2 desktop applications.

## Features

- Ed25519 signed license leases (offline grace, revocation, unlock orders).
- Admin dashboard with license keys, installations, heartbeats, audit log.
- Release/update management with optional mandatory flags.
- One-installation hardware binding.
- Session-based admin authentication with bcrypt password hashing.
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

This repository is the application root. Push changes to GitHub and deploy this repo directly in Coolify (no base directory needed).

```bash
git add .
git commit -m "N2 License Server update"
git push
```

### 2. Create the application in Coolify

1. Open your Coolify dashboard.
2. **Add a new Resource** → **Application**.
3. Choose **Private Repository** and select this repository (`greemlin/n2-license-server`).
4. Set **Build Pack** to `Docker Compose`.
5. The compose file `docker-compose.yml` is already configured for Coolify (internal port `8000`, no host-port binding, persistent volume).
6. Expose port `8000` (Coolify will route its proxy to this internal port).
7. Add your domain, for example:
   - `n2.systems`, or
   - `license.n2.systems`
8. Enable **HTTPS** / **Let's Encrypt**.
9. Add a **Persistent Volume** mounted at `/app/data` so the SQLite DB and Ed25519 keys survive redeploys.

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

If you use `license.n2.systems`, add an **A record** pointing to `46.4.65.32`.
If you use `n2.systems` itself, ensure its A record already points to `46.4.65.32`.

### 5. Deploy

Click **Deploy** in Coolify. The app should start on internal port `8000` and be reachable at `https://<your-domain>`.

Verify:

```bash
curl https://n2.systems/admin/health
# expected: {"status":"ok"}
```

### 6. First-run setup

1. Open `https://n2.systems/admin`.
2. Log in with the username + password from step 3.
3. The Ed25519 key pair is generated automatically on first start and stored in `/app/data/keys`. Because `/app/data` is a persistent volume, the same keys are kept across redeploys.
4. Create your first license key from the **License Keys** page.

### 7. Configure ThaliaMed

In `config/default.toml` (or the production config), point the desktop app to:

```toml
[license]
server_url = "https://n2.systems"
```

The app will call:

- `POST https://n2.systems/api/license/sync`
- `POST https://n2.systems/api/license/ack`

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

- Keep `data/keys/private.pem` secret and backed up.
- Rotate `SECRET_KEY` and admin password before production.
- Run behind HTTPS; set `secure` cookies in production (`DEBUG=false`).
- Do **not** publish host port `8000`; let Coolify route internally.
- Back up the persistent `/app/data` volume.

## Backups

Persist `data/license_server.db` and `data/keys/private.pem`.
