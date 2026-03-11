# Eartheye

Eartheye is an AI-powered attack-surface discovery and vulnerability scanning platform with a React frontend and FastAPI backend.

This project is already built. The steps below prepare it for **production deployment** at:

- `https://www.eartheye.com` (frontend)
- `https://api.eartheye.com` (backend API recommended)

---

## Production Architecture

- **Frontend**: Vite/React deployed on **Vercel**
- **Backend API**: FastAPI deployed on a **Linux VPS**
- **Database**: PostgreSQL (managed or self-hosted)
- **Scan storage**: filesystem path configured by `SCAN_STORAGE_PATH`

---

## Environment Variables

Copy `.env.example` to `.env` at the repo root and set real values.

Required keys:

- `DATABASE_URL`
- `JWT_SECRET`
- `API_URL`
- `SCAN_STORAGE_PATH`

Recommended production keys:

- `CORS_ORIGINS`
- `ALLOWED_HOSTS`
- `DEFAULT_ADMIN_EMAIL`
- `DEFAULT_ADMIN_PASSWORD`
- `RATE_LIMIT_WINDOW_SECONDS`
- `RATE_LIMIT_GLOBAL_REQUESTS`
- `RATE_LIMIT_AUTH_REQUESTS`
- `RATE_LIMIT_SCAN_CREATE_REQUESTS`
- `ALLOW_PRIVATE_SCAN_TARGETS`

Frontend env (inside Vercel project settings):

- `VITE_API_URL=https://api.eartheye.com`
  - `NEXT_PUBLIC_API_URL` is also supported as an alias.

---

## 1) Frontend Deployment on Vercel

1. Push this repository to GitHub.
2. In Vercel, click **Add New Project** and import the GitHub repository.
3. Set the frontend root directory to `frontend`.
4. Confirm build settings:
	- Build command: `npm run build`
	- Output directory: `dist`
5. Add environment variable:
	- `VITE_API_URL=https://api.eartheye.com`
6. Deploy.

The project includes `frontend/vercel.json` for SPA routing and production build output.

---

## 2) Backend Deployment on a Linux VPS

### Server prerequisites

- Ubuntu/Debian VPS
- Python 3.11+
- PostgreSQL access
- Optional scanner binaries (`subfinder`, `httpx`, `katana`, `gau`, `ffuf`, `nuclei`)

### Deploy steps

1. Clone repository on VPS.
2. Create and activate virtual environment.
3. Install backend dependencies:
	- `pip install -r requirements.txt`
4. Create `.env` from `.env.example` and set production values.
5. Start API from repo root:
	- `uvicorn main:app --host 0.0.0.0 --port 8000`

> `main.py` at the project root exposes `app` from `backend.main`, so `uvicorn main:app` works directly.

### systemd service (recommended)

Create `/etc/systemd/system/eartheye.service` and run the app with your venv Python/uvicorn. Then:

- `sudo systemctl daemon-reload`
- `sudo systemctl enable eartheye`
- `sudo systemctl start eartheye`
- `sudo systemctl status eartheye`

Use Nginx/Caddy in front of Uvicorn for TLS termination and reverse proxying.

---

## 3) Domain Configuration (`eartheye.com`)

### Connect GitHub repo to Vercel

1. Open Vercel project settings.
2. Confirm GitHub repo linkage and automatic deploys from `main`.

### Add custom domains in Vercel

Add:

- `www.eartheye.com`
- `eartheye.com` (apex)

### DNS records (example)

Use your DNS provider (Cloudflare/Namecheap/etc.) and configure records similar to:

- `A` record for backend host (example):
  - `api.eartheye.com` → `<YOUR_VPS_PUBLIC_IP>`
- `CNAME` record for frontend host:
  - `www.eartheye.com` → `cname.vercel-dns.com`

For apex `eartheye.com`, use Vercel’s instructed apex record (A/ALIAS/ANAME depending on DNS provider), and optionally redirect apex → `www`.

---

## 4) Production Security Safeguards Included

The codebase is now prepared with the following hardening controls:

1. **Rate limiting**
	- Global and route-specific API rate limits (auth and scan creation)
	- Configurable via env variables (`RATE_LIMIT_*`)

2. **Input validation**
	- Strict scan type validation
	- Domain format validation
	- Password and automation payload constraints

3. **Domain verification before scanning**
	- Targets must resolve in public DNS
	- Targets resolving only to private/non-routable IPs are blocked by default
	- Can be overridden only with `ALLOW_PRIVATE_SCAN_TARGETS=true`

4. **Admin route protection**
	- Frontend `/admin` route requires admin role
	- Backend `/api/admin/*` routes require admin auth (`get_current_admin`)

---

## 5) Notes for Live Operation

- End users do **not** install scanner tools locally.
- Scanner binaries are installed only on the backend host (or containers).
- If optional binaries are unavailable, built-in fallback discovery still runs.

