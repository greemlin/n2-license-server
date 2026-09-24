"""Admin web dashboard and API for the N2 License Server."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pyotp
from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
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
    hash_password,
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
    Product,
    Release,
)

router = APIRouter(prefix="/admin")
templates = Jinja2Templates(directory="app/templates")
login_limiter = Limiter(key_func=get_remote_address)
MAX_FAILED_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_MINUTES = 15
MIN_PASSWORD_LENGTH = 12
MAX_PRODUCT_CODE_LENGTH = 64


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
    """Generate a non-predictable, high-entropy license key with checksum."""
    import os

    settings = get_settings()
    prefix = settings.key_prefix or "THAL"
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    size = len(alphabet)

    payload = ""
    for _ in range(25):
        payload += alphabet[int.from_bytes(os.urandom(1), "big") % size]

    checksum = sum(alphabet.index(ch) for ch in payload) % size
    parts = [prefix]
    for i in range(0, 25, 5):
        parts.append(payload[i : i + 5])
    parts.append(alphabet[checksum])
    return "-".join(parts)


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _paging(page: int, per_page: int) -> tuple[int, int]:
    safe_page = max(page, 1)
    safe_per_page = min(max(per_page, 10), 100)
    return safe_page, safe_per_page


def _owner_only(admin: Any) -> None:
    if not admin or not admin.is_owner:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Owner access required")


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

    total_keys = db.scalar(select(func.count(LicenseKey.id)).where(LicenseKey.is_deleted == False))
    active_keys = db.scalar(select(func.count(LicenseKey.id)).where(LicenseKey.revoked == False, LicenseKey.is_deleted == False))
    revoked_keys = db.scalar(select(func.count(LicenseKey.id)).where(LicenseKey.revoked == True, LicenseKey.is_deleted == False))
    total_installations = db.scalar(select(func.count(Installation.id)).where(Installation.is_deleted == False))
    online_installations = db.scalar(
        select(func.count(Installation.id)).where(Installation.last_heartbeat_at >= last_24h, Installation.is_deleted == False)
    )
    locked_installations = db.scalar(
        select(func.count(Installation.id)).where(Installation.locked == True, Installation.is_deleted == False)
    )
    recent_heartbeats = db.scalars(
        select(Installation)
        .where(Installation.last_heartbeat_at >= last_24h, Installation.is_deleted == False)
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
# Products
# --------------------------------------------------------------------------- #


@router.get("/products", response_class=HTMLResponse)
@admin_required
async def list_products(request: Request, admin: Any = None, db: Session = Depends(get_db), page: int = Query(1, ge=1), per_page: int = Query(25, ge=10, le=100), q: str = Query("", max_length=128), sort: str = Query("name"), direction: str = Query("asc"), show_deleted: bool = Query(False)) -> HTMLResponse:
    _owner_only(admin)
    page, per_page = _paging(page, per_page)
    sortable: dict[str, Any] = {"name": Product.name, "code": Product.code, "created_at": Product.created_at}
    sort_column: Any = sortable.get(sort, Product.name)
    sort_column = sort_column.asc() if direction == "asc" else sort_column.desc()
    filters = [Product.is_deleted == show_deleted]
    if q:
        filters.append((Product.code.contains(q.upper())) | (Product.name.contains(q)) | (Product.description.contains(q)))
    total = db.scalar(select(func.count(Product.id)).where(*filters)) or 0
    products = db.scalars(select(Product).where(*filters).order_by(sort_column).offset((page - 1) * per_page).limit(per_page)).all()
    return templates.TemplateResponse(request, "products.html", {"request": request, "title": "Products", "admin": admin, "products": products, "page": page, "per_page": per_page, "total": total, "q": q, "sort": sort, "direction": direction, "show_deleted": show_deleted})


@router.get("/products/new", response_class=HTMLResponse)
@admin_required
async def new_product_page(request: Request, admin: Any = None) -> HTMLResponse:
    _owner_only(admin)
    return templates.TemplateResponse(request, "product_form.html", {"request": request, "title": "Create Product", "admin": admin, "product": None})


@router.post("/products")
@admin_required
async def create_product(request: Request, admin: Any = None, db: Session = Depends(get_db), code: str = Form(...), name: str = Form(...), description: str = Form("")) -> Any:
    _owner_only(admin)
    code = code.strip().upper()
    if not code or not code.replace("_", "").replace("-", "").isalnum() or len(code) > MAX_PRODUCT_CODE_LENGTH:
        raise HTTPException(status_code=422, detail="Invalid product code")
    if db.scalar(select(Product).where(Product.code == code)):
        raise HTTPException(status_code=409, detail="Product code already exists")
    product = Product(code=code, name=name.strip(), description=description.strip() or None)
    db.add(product)
    db.commit()
    db.refresh(product)
    log_audit("product_created", actor=admin.username, entity_type="product", entity_id=product.id, ip_address=_get_client_ip(request), details=code)
    return RedirectResponse(url="/admin/products", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/products/{product_id}/disable")
@admin_required
async def disable_product(request: Request, product_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    _owner_only(admin)
    product = db.get(Product, product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    product.is_active = False
    db.commit()
    log_audit("product_disabled", actor=admin.username, entity_type="product", entity_id=product.id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/products", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/products/{product_id}/enable")
@admin_required
async def enable_product(request: Request, product_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    _owner_only(admin)
    product = db.get(Product, product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    product.is_active = True
    db.commit()
    log_audit("product_enabled", actor=admin.username, entity_type="product", entity_id=product.id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/products", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/products/{product_id}/delete")
@admin_required
async def delete_product(request: Request, product_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    _owner_only(admin)
    product = db.get(Product, product_id)
    if not product or product.code == "THALIANET":
        raise HTTPException(status_code=400, detail="The default product cannot be deleted")
    product.is_deleted = True
    product.deleted_at = datetime.now(UTC).replace(tzinfo=None)
    product.is_active = False
    db.commit()
    log_audit("product_soft_deleted", actor=admin.username, entity_type="product", entity_id=product.id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/products", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/products/{product_id}/restore")
@admin_required
async def restore_product(request: Request, product_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    _owner_only(admin)
    product = db.get(Product, product_id)
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    product.is_deleted = False
    product.deleted_at = None
    product.is_active = True
    db.commit()
    log_audit("product_restored", actor=admin.username, entity_type="product", entity_id=product.id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/products?show_deleted=true", status_code=status.HTTP_303_SEE_OTHER)


# --------------------------------------------------------------------------- #
# License keys
# --------------------------------------------------------------------------- #


@router.get("/keys", response_class=HTMLResponse)
@admin_required
async def list_keys(
    request: Request,
    admin: Any = None,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=10, le=100),
    q: str = Query("", max_length=128),
    sort: str = Query("created_at"),
    direction: str = Query("desc"),
    show_deleted: bool = Query(False),
) -> HTMLResponse:
    page, per_page = _paging(page, per_page)
    sortable = {"created_at": LicenseKey.created_at, "edition": LicenseKey.edition, "activation_count": LicenseKey.activation_count, "expires_at": LicenseKey.expires_at}
    sort_column: Any = sortable.get(sort, LicenseKey.created_at)
    sort_column = sort_column.asc() if direction == "asc" else sort_column.desc()
    filters = [LicenseKey.is_deleted == show_deleted]
    if q:
        filters.append((LicenseKey.key_text.contains(q)) | (LicenseKey.label.contains(q)))
    total = db.scalar(select(func.count(LicenseKey.id)).where(*filters)) or 0
    keys = db.scalars(select(LicenseKey).where(*filters).order_by(sort_column).offset((page - 1) * per_page).limit(per_page)).all()
    return templates.TemplateResponse(request, "keys.html", {"request": request, "title": "License Keys", "admin": admin, "keys": keys, "now": datetime.now(UTC).replace(tzinfo=None), "page": page, "per_page": per_page, "total": total, "q": q, "sort": sort, "direction": direction, "show_deleted": show_deleted})


@router.get("/keys/new", response_class=HTMLResponse)
@admin_required
async def new_key_page(request: Request, admin: Any = None, db: Session = Depends(get_db)) -> HTMLResponse:
    products = db.scalars(select(Product).where(Product.is_active == True, Product.is_deleted == False).order_by(Product.name.asc())).all()
    return templates.TemplateResponse(request, "key_form.html", {"request": request, "title": "Create License Key", "admin": admin, "key": None, "products": products})


@router.post("/keys")
@admin_required
async def create_key(
    request: Request,
    admin: Any = None,
    db: Session = Depends(get_db),
    product_code: str = Form("THALIANET"),
    edition: str = Form("standard"),
    activation_limit: int = Form(1),
    offline_grace_days: int = Form(10),
    expires_at: str = Form(""),
    never_expires: str = Form(""),
    label: str = Form(""),
    note: str = Form(""),
) -> Any:
    product_code = product_code.strip().upper()
    product = db.scalar(select(Product).where(Product.code == product_code, Product.is_active == True, Product.is_deleted == False))
    if product is None:
        raise HTTPException(status_code=422, detail="Product is not active or does not exist")
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
        product_code=product_code,
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
        details=f"product={product_code}, edition={edition}, limit={activation_limit}, grace={offline_grace_days}, expires={expiry_text}",
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


@router.get("/keys/{key_id}/edit", response_class=HTMLResponse)
@admin_required
async def edit_key_page(
    request: Request,
    key_id: str,
    admin: Any = None,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    key = db.get(LicenseKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    return templates.TemplateResponse(
        request,
        "key_edit.html",
        {
            "request": request,
            "title": "Edit License Key",
            "admin": admin,
            "key": key,
        },
    )


@router.post("/keys/{key_id}/edit")
@admin_required
async def edit_key(
    request: Request,
    key_id: str,
    admin: Any = None,
    db: Session = Depends(get_db),
    activation_limit: int = Form(1),
    offline_grace_days: int = Form(10),
    expires_at: str = Form(""),
    never_expires: str = Form(""),
    label: str = Form(""),
    note: str = Form(""),
) -> Any:
    key = db.get(LicenseKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    expires_dt: datetime | None = None
    if not never_expires and expires_at:
        try:
            expires_dt = datetime.strptime(expires_at, "%Y-%m-%d")
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Invalid expiration date. Use YYYY-MM-DD.") from exc

    key.activation_limit = max(activation_limit, 1)
    key.offline_grace_days = max(offline_grace_days, 1)
    key.expires_at = expires_dt
    key.label = label or None
    key.note = note or None
    db.commit()

    expiry_text = "never" if key.expires_at is None else key.expires_at.strftime("%Y-%m-%d")
    log_audit(
        "key_updated",
        actor=admin.username,
        entity_type="license_key",
        entity_id=key.id,
        ip_address=_get_client_ip(request),
        details=f"limit={key.activation_limit}, grace={key.offline_grace_days}, expires={expiry_text}",
    )
    return RedirectResponse(url=f"/admin/keys/{key.id}", status_code=status.HTTP_303_SEE_OTHER)


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
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=10, le=100),
    q: str = Query("", max_length=128),
    sort: str = Query("last_seen_at"),
    direction: str = Query("desc"),
    show_deleted: bool = Query(False),
) -> HTMLResponse:
    page, per_page = _paging(page, per_page)
    sortable = {"last_seen_at": Installation.last_seen_at, "first_seen_at": Installation.first_seen_at, "app_version": Installation.app_version}
    sort_column: Any = sortable.get(sort, Installation.last_seen_at)
    sort_column = sort_column.asc() if direction == "asc" else sort_column.desc()
    filters = [Installation.is_deleted == show_deleted]
    if q:
        filters.append((Installation.installation_id.contains(q)) | (Installation.machine_fingerprint.contains(q)) | (Installation.platform.contains(q)))
    total = db.scalar(select(func.count(Installation.id)).where(*filters)) or 0
    installations = db.scalars(select(Installation).where(*filters).order_by(sort_column.nulls_last()).offset((page - 1) * per_page).limit(per_page)).all()
    return templates.TemplateResponse(request, "installations.html", {"request": request, "title": "Installations", "admin": admin, "installations": installations, "page": page, "per_page": per_page, "total": total, "q": q, "sort": sort, "direction": direction, "show_deleted": show_deleted})


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
async def list_releases(
    request: Request,
    admin: Any = None,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=10, le=100),
    q: str = Query("", max_length=128),
    sort: str = Query("published_at"),
    direction: str = Query("desc"),
    show_deleted: bool = Query(False),
) -> HTMLResponse:
    page, per_page = _paging(page, per_page)
    sortable = {"published_at": Release.published_at, "version": Release.version, "channel": Release.channel}
    sort_column: Any = sortable.get(sort, Release.published_at)
    sort_column = sort_column.asc() if direction == "asc" else sort_column.desc()
    filters = [Release.is_deleted == show_deleted]
    if q:
        filters.append((Release.version.contains(q)) | (Release.channel.contains(q)) | (Release.changelog.contains(q)))
    total = db.scalar(select(func.count(Release.id)).where(*filters)) or 0
    releases = db.scalars(select(Release).where(*filters).order_by(sort_column).offset((page - 1) * per_page).limit(per_page)).all()
    return templates.TemplateResponse(request, "releases.html", {"request": request, "title": "Releases", "admin": admin, "releases": releases, "page": page, "per_page": per_page, "total": total, "q": q, "sort": sort, "direction": direction, "show_deleted": show_deleted})


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
# Admin users
# --------------------------------------------------------------------------- #


@router.get("/users", response_class=HTMLResponse)
@admin_required
async def list_users(
    request: Request,
    admin: Any = None,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=10, le=100),
    q: str = Query("", max_length=128),
    sort: str = Query("created_at"),
    direction: str = Query("desc"),
    show_deleted: bool = Query(False),
) -> HTMLResponse:
    _owner_only(admin)
    page, per_page = _paging(page, per_page)
    sortable = {"created_at": AdminUser.created_at, "username": AdminUser.username, "last_login_at": AdminUser.last_login_at, "role": AdminUser.role}
    sort_column: Any = sortable.get(sort, AdminUser.created_at)
    sort_column = sort_column.asc() if direction == "asc" else sort_column.desc()
    filters = [AdminUser.is_deleted == show_deleted]
    if q:
        filters.append((AdminUser.username.contains(q)) | (AdminUser.role.contains(q)))
    total = db.scalar(select(func.count(AdminUser.id)).where(*filters)) or 0
    users = db.scalars(select(AdminUser).where(*filters).order_by(sort_column).offset((page - 1) * per_page).limit(per_page)).all()
    return templates.TemplateResponse(request, "users.html", {"request": request, "title": "Admin Users", "admin": admin, "users": users, "page": page, "per_page": per_page, "total": total, "q": q, "sort": sort, "direction": direction, "show_deleted": show_deleted})


@router.get("/users/new", response_class=HTMLResponse)
@admin_required
async def new_user_page(request: Request, admin: Any = None) -> HTMLResponse:
    _owner_only(admin)
    return templates.TemplateResponse(request, "user_form.html", {"request": request, "title": "Create Admin User", "admin": admin, "user": None})


@router.post("/users")
@admin_required
async def create_user(
    request: Request,
    admin: Any = None,
    db: Session = Depends(get_db),
    username: str = Form(...),
    password: str = Form(...),
    role: str = Form("admin"),
) -> Any:
    _owner_only(admin)
    username = username.strip()
    if role not in {"admin", "viewer"} or len(password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=422, detail="Invalid role or password must be at least 12 characters")
    if db.scalar(select(AdminUser).where(AdminUser.username == username)):
        raise HTTPException(status_code=409, detail="Username already exists")
    user = AdminUser(username=username, password_hash=hash_password(password), role=role, is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_audit("user_created", actor=admin.username, entity_type="admin_user", entity_id=user.id, ip_address=_get_client_ip(request), details=f"role={role}")
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)


@router.get("/users/{user_id}/edit", response_class=HTMLResponse)
@admin_required
async def edit_user_page(request: Request, user_id: str, admin: Any = None, db: Session = Depends(get_db)) -> HTMLResponse:
    _owner_only(admin)
    user = db.get(AdminUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return templates.TemplateResponse(request, "user_form.html", {"request": request, "title": "Edit Admin User", "admin": admin, "user": user})


@router.post("/users/{user_id}/edit")
@admin_required
async def edit_user(
    request: Request,
    user_id: str,
    admin: Any = None,
    db: Session = Depends(get_db),
    password: str = Form(""),
    role: str = Form("admin"),
    is_active: str = Form(""),
) -> Any:
    _owner_only(admin)
    user = db.get(AdminUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.username == admin.username and (is_active == "" or role != "owner"):
        raise HTTPException(status_code=422, detail="The owner account cannot be disabled or downgraded")
    if role not in {"owner", "admin", "viewer"}:
        raise HTTPException(status_code=422, detail="Invalid role")
    user.role = role
    user.is_active = bool(is_active)
    if password:
        if len(password) < MIN_PASSWORD_LENGTH:
            raise HTTPException(status_code=422, detail="Password must be at least 12 characters")
        user.password_hash = hash_password(password)
    db.commit()
    log_audit("user_updated", actor=admin.username, entity_type="admin_user", entity_id=user.id, ip_address=_get_client_ip(request), details=f"role={role}, active={user.is_active}")
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/2fa/enable")
@admin_required
async def enable_user_2fa(request: Request, user_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    _owner_only(admin)
    user = db.get(AdminUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.otp_secret = pyotp.random_base32()
    user.otp_enabled = True
    db.commit()
    log_audit("user_2fa_enabled", actor=admin.username, entity_type="admin_user", entity_id=user.id, ip_address=_get_client_ip(request))
    return templates.TemplateResponse(request, "user_2fa.html", {"request": request, "title": "2FA Enabled", "admin": admin, "user": user, "secret": user.otp_secret, "uri": pyotp.TOTP(user.otp_secret).provisioning_uri(name=user.username, issuer_name="N2 License Server")})


@router.post("/users/{user_id}/2fa/disable")
@admin_required
async def disable_user_2fa(request: Request, user_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    _owner_only(admin)
    user = db.get(AdminUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.otp_secret = None
    user.otp_enabled = False
    db.commit()
    log_audit("user_2fa_disabled", actor=admin.username, entity_type="admin_user", entity_id=user.id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/delete")
@admin_required
async def delete_user(request: Request, user_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    _owner_only(admin)
    user = db.get(AdminUser, user_id)
    if not user or user.username == admin.username or user.role == "owner":
        raise HTTPException(status_code=400, detail="Owner accounts cannot be deleted")
    user.is_deleted = True
    user.deleted_at = datetime.now(UTC).replace(tzinfo=None)
    user.is_active = False
    db.commit()
    log_audit("user_soft_deleted", actor=admin.username, entity_type="admin_user", entity_id=user.id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/users/{user_id}/restore")
@admin_required
async def restore_user(request: Request, user_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    _owner_only(admin)
    user = db.get(AdminUser, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_deleted = False
    user.deleted_at = None
    user.is_active = True
    db.commit()
    log_audit("user_restored", actor=admin.username, entity_type="admin_user", entity_id=user.id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/users?show_deleted=true", status_code=status.HTTP_303_SEE_OTHER)


# --------------------------------------------------------------------------- #
# Soft delete / restore
# --------------------------------------------------------------------------- #


def _soft_delete_entity(db: Session, entity: Any) -> None:
    entity.is_deleted = True
    entity.deleted_at = datetime.now(UTC).replace(tzinfo=None)
    db.commit()


@router.post("/keys/{key_id}/delete")
@admin_required
async def delete_key(request: Request, key_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    key = db.get(LicenseKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    _soft_delete_entity(db, key)
    log_audit("key_soft_deleted", actor=admin.username, entity_type="license_key", entity_id=key_id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/keys", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/keys/{key_id}/restore")
@admin_required
async def restore_key(request: Request, key_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    key = db.get(LicenseKey, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    key.is_deleted = False
    key.deleted_at = None
    db.commit()
    log_audit("key_restored", actor=admin.username, entity_type="license_key", entity_id=key_id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/keys?show_deleted=true", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/installations/{installation_id}/delete")
@admin_required
async def delete_installation(request: Request, installation_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    inst = db.scalar(select(Installation).where(Installation.installation_id == installation_id))
    if not inst:
        raise HTTPException(status_code=404, detail="Installation not found")
    _soft_delete_entity(db, inst)
    log_audit("installation_soft_deleted", actor=admin.username, entity_type="installation", entity_id=installation_id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/installations", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/installations/{installation_id}/restore")
@admin_required
async def restore_installation(request: Request, installation_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    inst = db.scalar(select(Installation).where(Installation.installation_id == installation_id))
    if not inst:
        raise HTTPException(status_code=404, detail="Installation not found")
    inst.is_deleted = False
    inst.deleted_at = None
    db.commit()
    log_audit("installation_restored", actor=admin.username, entity_type="installation", entity_id=installation_id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/installations?show_deleted=true", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/releases/{release_id}/delete")
@admin_required
async def delete_release(request: Request, release_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    release = db.get(Release, release_id)
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    _soft_delete_entity(db, release)
    log_audit("release_soft_deleted", actor=admin.username, entity_type="release", entity_id=release_id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/releases", status_code=status.HTTP_303_SEE_OTHER)


@router.post("/releases/{release_id}/restore")
@admin_required
async def restore_release(request: Request, release_id: str, admin: Any = None, db: Session = Depends(get_db)) -> Any:
    release = db.get(Release, release_id)
    if not release:
        raise HTTPException(status_code=404, detail="Release not found")
    release.is_deleted = False
    release.deleted_at = None
    db.commit()
    log_audit("release_restored", actor=admin.username, entity_type="release", entity_id=release_id, ip_address=_get_client_ip(request))
    return RedirectResponse(url="/admin/releases?show_deleted=true", status_code=status.HTTP_303_SEE_OTHER)


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #


@router.get("/audit", response_class=HTMLResponse)
@admin_required
async def audit_log(
    request: Request,
    admin: Any = None,
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=10, le=100),
    q: str = Query("", max_length=128),
    sort: str = Query("timestamp"),
    direction: str = Query("desc"),
) -> HTMLResponse:
    page, per_page = _paging(page, per_page)
    sortable = {"timestamp": AuditLog.timestamp, "action": AuditLog.action, "actor": AuditLog.actor}
    sort_column: Any = sortable.get(sort, AuditLog.timestamp)
    sort_column = sort_column.asc() if direction == "asc" else sort_column.desc()
    filters = []
    if q:
        filters.append((AuditLog.action.contains(q)) | (AuditLog.actor.contains(q)) | (AuditLog.details.contains(q)))
    total = db.scalar(select(func.count(AuditLog.id)).where(*filters)) or 0
    logs = db.scalars(select(AuditLog).where(*filters).order_by(sort_column).offset((page - 1) * per_page).limit(per_page)).all()
    return templates.TemplateResponse(request, "audit.html", {"request": request, "title": "Audit Log", "admin": admin, "logs": logs, "page": page, "per_page": per_page, "total": total, "q": q, "sort": sort, "direction": direction})


# --------------------------------------------------------------------------- #
# Health / key generation helper
# --------------------------------------------------------------------------- #


@router.get("/health")
def admin_health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready")
def admin_ready(db: Session = Depends(get_db)) -> dict[str, str]:
    settings = get_settings()
    db.scalar(select(func.count(Product.id)))
    if not (settings.keys_dir / "private.pem").exists() or not (settings.keys_dir / "public.pem").exists():
        raise HTTPException(status_code=503, detail="signing_keys_unavailable")
    return {"status": "ready"}


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
