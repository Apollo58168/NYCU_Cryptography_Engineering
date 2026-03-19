"""
Phase 2 – Symmetric 2FA (TOTP) login system.

Routes
------
GET  /                  Home page
GET  /register          Registration form
POST /register          Create account, generate TOTP secret, show QR code
GET  /login             Login form (step 1: password)
POST /login             Verify password → redirect to TOTP verification
GET  /verify-totp       TOTP verification form (step 2)
POST /verify-totp       Verify TOTP code → redirect to dashboard
GET  /dashboard         Protected page for authenticated users
GET  /logout            Clear session and redirect home

Session flow
------------
After a successful password check the session is marked as "totp_pending".
After a successful TOTP check it is upgraded to "authenticated".
Both steps must succeed before a user can access /dashboard.
"""

import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .auth import hash_password, verify_password
from .database import engine, get_db
from .models import Base, User
from .totp import (
    generate_otpauth_uri,
    generate_qr_code_b64,
    generate_secret,
    get_totp_token,
    verify_totp,
)

# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Phase 2 – TOTP 2FA")

_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# In-memory session store.
# Key   : session_id (cryptographically random URL-safe token)
# Value : {"username": str, "step": "totp_pending" | "authenticated"}
_sessions: dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def _get_session(request: Request) -> dict:
    sid = request.cookies.get("session_id", "")
    return _sessions.get(sid, {})


def _set_session(response, sid: str, data: dict) -> None:
    _sessions[sid] = data
    response.set_cookie("session_id", sid, httponly=True, samesite="lax")


# ---------------------------------------------------------------------------
# Home
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    session = _get_session(request)
    username = session.get("username") if session.get("step") == "authenticated" else None
    return templates.TemplateResponse(
        "index.html", {"request": request, "username": username}
    )


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------

@app.get("/register", response_class=HTMLResponse)
async def register_form(request: Request):
    return templates.TemplateResponse(
        "register.html", {"request": request, "error": None}
    )


@app.post("/register", response_class=HTMLResponse)
async def register(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    # Basic input sanitisation
    username = username.strip()
    if not username or not password:
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Username and password are required."},
        )

    if db.query(User).filter(User.username == username).first():
        return templates.TemplateResponse(
            "register.html",
            {"request": request, "error": "Username already taken. Please choose another."},
        )

    secret = generate_secret()
    user = User(
        username=username,
        password_hash=hash_password(password),
        totp_secret=secret,
    )
    db.add(user)
    db.commit()

    otpauth = generate_otpauth_uri(secret, username)
    qr_b64 = generate_qr_code_b64(otpauth)
    # Show the current TOTP code so the user can confirm their setup is correct
    current_code = get_totp_token(secret)

    return templates.TemplateResponse(
        "register_success.html",
        {
            "request": request,
            "username": username,
            "secret": secret,
            "otpauth": otpauth,
            "qr_b64": qr_b64,
            "current_code": current_code,
        },
    )


# ---------------------------------------------------------------------------
# Login – Step 1: password
# ---------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse(
        "login.html", {"request": request, "error": None}
    )


@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    username = username.strip()
    user = db.query(User).filter(User.username == username).first()

    # Deliberate generic error – do not reveal whether the username exists
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid username or password."},
        )

    # Password OK → create a *pending* session (TOTP not yet verified)
    sid = secrets.token_urlsafe(32)
    response = RedirectResponse(url="/verify-totp", status_code=303)
    _set_session(response, sid, {"username": username, "step": "totp_pending"})
    return response


# ---------------------------------------------------------------------------
# Login – Step 2: TOTP
# ---------------------------------------------------------------------------

@app.get("/verify-totp", response_class=HTMLResponse)
async def verify_totp_form(request: Request):
    session = _get_session(request)
    if session.get("step") != "totp_pending":
        return RedirectResponse(url="/login")
    return templates.TemplateResponse(
        "verify_totp.html",
        {"request": request, "username": session["username"], "error": None},
    )


@app.post("/verify-totp", response_class=HTMLResponse)
async def verify_totp_route(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db),
):
    sid = request.cookies.get("session_id", "")
    session = _sessions.get(sid, {})

    if session.get("step") != "totp_pending":
        return RedirectResponse(url="/login", status_code=303)

    username = session["username"]
    user = db.query(User).filter(User.username == username).first()

    # verify_totp allows ±1 time step (±30 seconds window)
    if not user or not verify_totp(user.totp_secret, code):
        return templates.TemplateResponse(
            "verify_totp.html",
            {
                "request": request,
                "username": username,
                "error": "Invalid or expired code. Please try again.",
            },
        )

    # TOTP OK → upgrade session to fully authenticated
    _sessions[sid] = {"username": username, "step": "authenticated"}
    return RedirectResponse(url="/dashboard", status_code=303)


# ---------------------------------------------------------------------------
# Dashboard (protected)
# ---------------------------------------------------------------------------

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    session = _get_session(request)
    if session.get("step") != "authenticated":
        return RedirectResponse(url="/login")
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "username": session["username"]}
    )


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

@app.get("/logout")
async def logout(request: Request):
    sid = request.cookies.get("session_id", "")
    _sessions.pop(sid, None)
    response = RedirectResponse(url="/")
    response.delete_cookie("session_id")
    return response
