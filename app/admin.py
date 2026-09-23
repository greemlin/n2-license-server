"""Admin web dashboard and API for the N2 License Server."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.auth import (
    admin_required,
    clear_pending_otp,
    clear_session,
    create_pending_otp_token,
    create_session,
    get_current_admin,
    get_pending_otp_username,
    log_audit,
    verify_password,
)
from app.config import get_settings
from app.crypto import (
    generate_keypair,
    generate_unlock_code,
    hash_key,
    load_private_key,
)
from app.database import SessionLocal
from app.models import (
    AdminUser,
    AuditLog,
    Installation,
    LicenseActivation,
    LicenseKey,
    LockOrder,
    LoginAttempt,
    Release,
)

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="app/templates")
login_limiter = Limiter(key_func=get_remote_address)
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15


# --------------------------------------------------------------------------- #
# Brute-force protection helpers
# --------------------------------------------------------------------------- #


def _recent_failed_logins(db: Session, ip_address: str, username: str) -> int:
    window = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=LOGIN_LOCKOUT_MINUTES)
    return db.scalar(
        select(func.count(LoginAttempt.id)).where(
            LoginAttempt.success == False,
            LoginAttempt.attempted_at >= window,
            ((LoginAttempt.ip_address == ip_address) | (LoginAttempt.username == username)),
        )
    ) or 0


def _record_login_attempt(db: Session, ip_address: str, username: str, success: bool) -> None:
    attempt = LoginAttempt(
        ip_address=ip_address,
        username=username,
        success=success,
    )
    db.add(attempt)
    db.commit()


def _login_blocked(db: Session, ip_address: str, username: str) -> bool:
    return _recent_failed_logins(db, ip_address, username) >= MAX_FAILED_LOGIN_ATTEMPTS


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def get_db() -> Any:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _generate_key_text() -> str:
    """Generate a human-readable license key."""
    import os

    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    parts = ["THAL"]
    for _ in range(4):
        parts.append("".join([alphabet[int(b) % 32] for b in os.urandom(4)]))
    return "-".join(parts)


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


# --------------------------------------------------------------------------- #
# Auth pages
# --------------------------------------------------------------------------- #


@router.get("/login", response_class=HTMLResponse, response_model=None)
def login_page(
    request: Request,
    error: str = "",
    db: Session = Depends(get_db),
) -> HTMLResponse | RedirectResponse:
    admin = get_current_admin(request)
    if admin:
        return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
    ip = _get_client_ip(request)
    blocked = _login_blocked(db, ip, "")
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "error": error,
            "title": "Admin Login",
            "blocked": blocked,
        },
    )


@router.post("/login")
@login_limiter.limit("10/minute")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
) -> Any:
    ip_address = _get_client_ip(request)

    if _login_blocked(db, ip_address, username):
        _record_login_attempt(db, ip_address, username, False)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "error": "Too many failed attempts. Wait 15 minutes or contact support.",
                "title": "Admin Login",
                "blocked": True,
            },
            status_code=429,
        )

    user = db.scalar(select(AdminUser).where(AdminUser.username == username))
    if user is None or user.is_deleted or not verify_password(password, user.password_hash):
        _record_login_attempt(db, ip_address, username, False)
        log_audit(
            "admin_login_failed",
            actor=username,
            ip_address=ip_address,
        )
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "error": "Invalid username or password.",
                "title": "Admin Login",
                "blocked": _login_blocked(db, ip_address, username),
            },
            status_code=401,
        )

    if not user.is_active:
        _record_login_attempt(db, ip_address, username, False)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "request": request,
                "error": "Account is disabled.",
                "title": "Admin Login",
                "blocked": False,
            },
            status_code=403,
        )

    _record_login_attempt(db, ip_address, username, True)

    if user.otp_enabled and user.otp_secret:
        redirect = RedirectResponse(url="/admin/login/2fa", status_code=status.HTTP_303_SEE_OTHER)
        create_pending_otp_token(redirect, username, secure=request.url.scheme == "https")
        return redirect

    redirect = RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
    create_session(redirect, username, secure=request.url.scheme == "https")
    return redirect


@router.get("/login/2fa", response_class=HTMLResponse, response_model=None)
def login_2fa_page(request: Request, error: str = "") -> Any:
    username = get_pending_otp_username(request)
    if not username:
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        request,
        "login_2fa.html",
        {
            "request": request,
            "error": error,
            "title": "Two-Factor Authentication",
        },
    )


@router.post("/login/2fa")
@login_limiter.limit("10/minute")
def login_2fa_submit(
    request: Request,
    code: str = Form(...),
    db: Session = Depends(get_db),
) -> Any:
    import pyotp

    username = get_pending_otp_username(request)
    if not username:
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_303_SEE_OTHER)

    user = db.scalar(select(AdminUser).where(AdminUser.username == username))
    if user is None or not user.otp_enabled or not user.otp_secret:
        return RedirectResponse(url="/admin/login", status_code=status.HTTP_303_SEE_OTHER)

    totp = pyotp.TOTP(user.otp_secret)
    if not totp.verify(code.strip(), valid_window=1):
        return templates.TemplateResponse(
            request,
            "login_2fa.html",
            {
                "request": request,
                "error": "Invalid verification code.",
                "title": "Two-Factor Authentication",
            },
            status_code=401,
        )

    redirect = RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
    clear_pending_otp(redirect)
    create_session(redirect, username, secure=request.url.scheme == "https")
    return redirect


@router.get("/logout", response_model=None)
def logout() -> Any:
    redirect = RedirectResponse(url="/admin/login", status_code=status.HTTP_303_SEE_OTHER)
    clear_session(redirect)
    return redirect


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #


@router.get("/", response_class=HTMLResponse)
@admin_required
async def dashboard(request: Request, admin: Any = None, db: Session = Depends(get_db)) -> HTMLResponse:
    now = datetime.now(UTC)
    last_24h = now - timedelta(hours=24)

    total_keys = db.scalar(select(func.count(LicenseKey.id)))
    active_keys = db.scalar(select(func.count(LicenseKey.id)).where(LicenseKey.revoked == False))
    revoked_keys = db.scalar(select(func.count(LicenseKey.id)).where(LicenseKey.revoked == True))
    total_installations = db.scalar(select(func.count(Installation.id)))
    online_installations = db.scalar(
        select(func.count(Installation.id)).where(Installation.last_heartbeat_at >= last_24h)
    )
    locked_installations = db.scalar(
        select(func.count(Installation.id)).where(Installation.locked == True)
    )
    recent_heartbeats = db.scalars(
        select(Installation)
        .where(Installation.last_heartbeat_at >= last_24h)
        .order_by(Installation.last_heartbeat_at.desc())
        .limit(10)
    ).all()
    recent_audits = db.scalars(
        select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(20)
    ).all()

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "request": request,
            "title": "Dashboard",
            "admin": admin,
            "stats": {
                "total_keys": total_keys,
                "active_keys": active_keys,
                "revoked_keys": revoked_keys,
                "total_installations": total_installations,
                "online_installations": online_installations,
                "locked_installations": locked_installations,
            },
            "recent_heartbeats": recent_heartbeats,
            "recent_audits": recent_audits,
        },
    )


# --------------------------------------------------------------------------- #
# License keys
# --------------------------------------------------------------------------- #


@router.get("/keys", response_class=HTMLResponse)
@admin_required
async def list_keys(request: Request, admin: Any = None, db: Session = Depends(get_db)) -> HTMLResponse:
    keys = db.scalars(select(LicenseKey).order_by(LicenseKey.created_at.desc())).all()
    return templates.TemplateResponse(
        request,
        "keys.html",
        {
            "request": request,
            "title": "License Keys",
            "admin": admin,
            "keys": keys,
            "now": datetime.now(UTC).replace(tzinfo=None),
        },
    )


@router.get("/keys/new", response_class=HTMLResponse)
@admin_required
async def new_key_page(request: Request, admin: Any = None) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "key_form.html",
        {
            "request": request,
            "title": "Create License Key",
            "admin": admin,
            "key": None,
        },
    )


@router.post("/keys")
@admin_required
async def create_key(
    request: Request,
    admin: Any = None,
    db: Session = Depends(get_db),
    edition: str = Form("standard"),
    activation_limit: int = Form(1),
    offline_grace_days: int = Form(10),
    expires_at: str = Form(""),
    never_expires: str = Form(""),
    label: str = Form(""),
    note: str = Form(""),
) -> Any:
    activation_limit = max(activation_limit, 1)
    offline_grace_days = max(offline_grace_days, 1)

    expires_dt: datetime | None = None
    if not never_expires and expires_at:
        try:
            expires_dt = datetime.strptime(expires_at, "%Y-%m-%d")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid expiration date. Use YYYY-MM-DD.") from exc

    for _ in range(5):
        key_text = _generate_key_text()
        key_hash = hash_key(key_text)
        existing = db.scalar(select(LicenseKey).where(LicenseKey.key_hash == key_hash))
        if not existing:
            break
    else:
        raise HTTPException(status_code=500, detail="Failed to generate unique key")

    key = LicenseKey(
        key_hash=key_hash,
        key_text=key_text,
        edition=edition,
        activation_limit=activation_limit,
        offline_grace_days=offline_grace_days,
        expires_at=expires_dt,
        label=label,
        note=note,
    )
    db.add(key)
    db.commit()
    db.refresh(key)

    expiry_text = "never" if key.expires_at is None else key.expires_at.strftime("%Y-%m-%d")
    log_audit(
        "key_created",
        actor=admin.username,
        entity_type="license_key",
        entity_id=key.id,
        ip_address=_get_client_ip(request),
        details=f"edition={edition}, limit={activation_limit}, grace={offline_grace_days}, expires={expiry_text}",
    )

    return RedirectResponse(url=f"/admin/keys/{key.id}", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/keys/{key_id}", response_class=HTMLResponse)
@admin_required
async def view_key(
    request: Request,
    key_id: str,
    admin: Any = None,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    key = db.get(LicenseKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    activations = db.scalars(
        select(LicenseActivation).where(LicenseActivation.license_key_id == key_id)
    ).all()
    installations = db.scalars(
        select(Installation).where(Installation.license_key_id == key_id)
    ).all()
    return templates.TemplateResponse(
        request,
        "key_detail.html",
        {
            "request": request,
            "title": f"Key {key.key_text}",
            "admin": admin,
            "key": key,
            "activations": activations,
            "installations": installations,
        },
    )


@router.post("/keys/{key_id}/revoke")
@admin_required
async def revoke_key(
    request: Request,
    key_id: str,
    admin: Any = None,
    db: Session = Depends(get_db),
) -> Any:
    key = db.get(LicenseKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    key.revoked = True
    key.revoked_at = datetime.now(UTC)

    activations = db.scalars(
        select(LicenseActivation).where(
            LicenseActivation.license_key_id == key_id,
            LicenseActivation.status == "active",
        )
    ).all()
    for act in activations:
        act.status = "revoked"
        inst = db.scalar(
            select(Installation).where(Installation.installation_id == act.installation_id)
        )
        if inst:
            inst.locked = True
            inst.locked_reason = "License key revoked"
            inst.locked_at = datetime.now(UTC)

    db.commit()
    log_audit(
        "key_revoked",
        actor=admin.username,
        entity_type="license_key",
        entity_id=key_id,
        ip_address=_get_client_ip(request),
    )
    return RedirectResponse(url=f"/admin/keys/{key_id}", status_code=status.HTTP_303_SEE_OTHER)


# --------------------------------------------------------------------------- #
# Installations
# --------------------------------------------------------------------------- #


@router.get("/installations", response_class=HTMLResponse)
@admin_required
async def list_installations(
    request: Request,
    admin: Any = None,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    installations = db.scalars(
        select(Installation).order_by(Installation.last_seen_at.desc().nulls_last())
    ).all()
    return templates.TemplateResponse(
        request,
        "installations.html",
        {
            "request": request,
            "title": "Installations",
            "admin": admin,
            "installations": installations,
        },
    )


@router.get("/installations/{installation_id}", response_class=HTMLResponse)
@admin_required
async def view_installation(
    request: Request,
    installation_id: str,
    admin: Any = None,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    inst = db.scalar(
        select(Installation).where(Installation.installation_id == installation_id)
    )
    if not inst:
        raise HTTPException(status_code=404, detail="Installation not found")
    key = db.get(LicenseKey, inst.license_key_id) if inst.license_key_id else None
    return templates.TemplateResponse(
        request,
        "installation_detail.html",
        {
            "request": request,
            "title": f"Installation {installation_id[:16]}...",
            "admin": admin,
            "installation": inst,
            "license_key": key,
        },
    )


@router.post("/installations/{installation_id}/lock")
@admin_required
async def lock_installation(
    request: Request,
    installation_id: str,
    admin: Any = None,
    db: Session = Depends(get_db),
    reason: str = Form("Locked by administrator"),
) -> Any:
    inst = db.scalar(
        select(Installation).where(Installation.installation_id == installation_id)
    )
    if not inst:
        raise HTTPException(status_code=404, detail="Installation not found")

    order = LockOrder(
        installation_id=installation_id,
        order_type="lock",
        reason=reason,
    )
    db.add(order)

    inst.locked = True
    inst.locked_reason = reason
    inst.locked_at = datetime.now(UTC)
    db.commit()

    log_audit(
        "installation_locked",
        actor=admin.username,
        entity_type="installation",
        entity_id=installation_id,
        ip_address=_get_client_ip(request),
        details=reason,
    )
    return RedirectResponse(url=f"/admin/installations/{installation_id}", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/installations/{installation_id}/unlock")
@admin_required
async def unlock_installation(
    request: Request,
    installation_id: str,
    admin: Any = None,
    db: Session = Depends(get_db),
    reason: str = Form("Unlocked by administrator"),
) -> Any:
    settings = get_settings()
    inst = db.scalar(
        select(Installation).where(Installation.installation_id == installation_id)
    )
    if not inst:
        raise HTTPException(status_code=404, detail="Installation not found")

    private_key = load_private_key(settings.keys_dir / "private.pem")
    key = db.get(LicenseKey, inst.license_key_id) if inst.license_key_id else None
    grace_days = key.offline_grace_days if key else settings.default_offline_grace_days
    unlock_code = generate_unlock_code(
        private_key,
        installation_id,
        validity_hours=48,
        offline_grace_days=grace_days,
    )

    order = LockOrder(
        installation_id=installation_id,
        order_type="unlock",
        reason=reason,
    )
    db.add(order)

    inst.locked = False
    inst.locked_reason = None
    inst.unlocked_at = datetime.now(UTC)
    db.commit()

    log_audit(
        "installation_unlocked",
        actor=admin.username,
        entity_type="installation",
        entity_id=installation_id,
        ip_address=_get_client_ip(request),
        details=reason,
    )
    return templates.TemplateResponse(
        request,
        "installation_detail.html",
        {
            "request": request,
            "title": f"Installation {installation_id[:16]}...",
            "admin": admin,
            "installation": inst,
            "license_key": key,
            "unlock_code": unlock_code,
            "message": "Installation unlocked. Share the one-time code with the customer.",
        },
    )


# --------------------------------------------------------------------------- #
# Releases / updates
# --------------------------------------------------------------------------- #


@router.get("/releases", response_class=HTMLResponse)
@admin_required
async def list_releases(request: Request, admin: Any = None, db: Session = Depends(get_db)) -> HTMLResponse:
    releases = db.scalars(select(Release).order_by(Release.published_at.desc())).all()
    return templates.TemplateResponse(
        request,
        "releases.html",
        {
            "request": request,
            "title": "Releases",
            "admin": admin,
            "releases": releases,
        },
    )


@router.get("/releases/new", response_class=HTMLResponse)
@admin_required
async def new_release_page(request: Request, admin: Any = None) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "release_form.html",
        {
            "request": request,
            "title": "Create Release",
            "admin": admin,
        },
    )


@router.post("/releases")
@admin_required
async def create_release(
    request: Request,
    admin: Any = None,
    db: Session = Depends(get_db),
    version: str = Form(...),
    channel: str = Form("stable"),
    download_url: str = Form(""),
    checksum_sha256: str = Form(""),
    changelog: str = Form(""),
    is_mandatory: str = Form(""),
) -> Any:
    release = Release(
        version=version,
        channel=channel,
        download_url=download_url or None,
        checksum_sha256=checksum_sha256 or None,
        changelog=changelog or None,
        is_mandatory=bool(is_mandatory),
    )
    db.add(release)
    db.commit()
    db.refresh(release)

    log_audit(
        "release_created",
        actor=admin.username,
        entity_type="release",
        entity_id=release.id,
        ip_address=_get_client_ip(request),
        details=f"version={version}, channel={channel}",
    )
    return RedirectResponse(url="/admin/releases", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/releases/{release_id}/revoke")
@admin_required
async def revoke_release(
    request: Request,
    release_id: str,
    admin: Any = None,
    db: Session = Depends(get_db),
) -> Any:
    release = db.get(Release, release_id)
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    release.revoked_at = datetime.now(UTC)
    db.commit()
    log_audit(
        "release_revoked",
        actor=admin.username,
        entity_type="release",
        entity_id=release_id,
        ip_address=_get_client_ip(request),
    )
    return RedirectResponse(url="/admin/releases", status_code=status.HTTP_303_SEE_OTHER)


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


@router.get("/audit", response_class=HTMLResponse)
@admin_required
async def audit_log(
    request: Request,
    admin: Any = None,
    db: Session = Depends(get_db),
    limit: int = 100,
) -> HTMLResponse:
    logs = db.scalars(
        select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    ).all()
    return templates.TemplateResponse(
        request,
        "audit.html",
        {
            "request": request,
            "title": "Audit Log",
            "admin": admin,
            "logs": logs,
        },
    )


# --------------------------------------------------------------------------- #
# Health / key generation helper
# --------------------------------------------------------------------------- #


@router.get("/health")
def admin_health() -> dict[str, str]:
    return {"status": "ok"}


@router.post("/generate-keys")
@admin_required
async def generate_keys(
    request: Request,
    admin: Any = None,
) -> Any:
    settings = get_settings()
    private_path = settings.keys_dir / "private.pem"
    public_path = settings.keys_dir / "public.pem"
    generate_keypair(private_path, public_path)
    log_audit(
        "keys_generated",
        actor=admin.username,
        ip_address=_get_client_ip(request),
    )
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)
