"""Session-based admin authentication and user management."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from typing import Any

import bcrypt
from fastapi import Request, Response
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy import select

from app.config import get_settings
from app.database import SessionLocal
from app.models import AdminUser, AuditLog


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().secret_key, salt="n2ls-admin-session")


def _otp_serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().secret_key, salt="n2ls-otp-pending")


def create_session(response: Response, username: str, secure: bool = True) -> None:
    settings = get_settings()
    token = _serializer().dumps({"username": username})
    response.set_cookie(
        key=settings.session_cookie_name,
        value=token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=settings.session_max_age_seconds,
    )


def clear_session(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(settings.session_cookie_name)


@dataclass
class AdminSession:
    username: str
    role: str = "admin"
    otp_enabled: bool = False
    is_active: bool = True

    @property
    def is_owner(self) -> bool:
        return self.role == "owner"

    @property
    def is_admin(self) -> bool:
        return self.role in ("owner", "admin")


def bootstrap_admin_user() -> None:
    """Create the initial owner from environment variables if no users exist."""
    settings = get_settings()
    if not settings.admin_username or not settings.admin_password_hash:
        return
    with SessionLocal() as db:
        existing = db.scalar(select(AdminUser).where(AdminUser.username == settings.admin_username))
        if existing is not None:
            existing.role = "owner"
            existing.is_active = True
            existing.is_deleted = False
            existing.deleted_at = None
            db.commit()
            return
        user = AdminUser(
            username=settings.admin_username,
            password_hash=settings.admin_password_hash,
            role="owner",
            is_active=True,
        )
        db.add(user)
        db.commit()


def get_current_admin(request: Request) -> AdminSession | None:
    settings = get_settings()
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        return None
    try:
        data = _serializer().loads(token, max_age=settings.session_max_age_seconds)
    except Exception:  # noqa: BLE001
        return None
    username = data.get("username")
    if not username:
        return None
    with SessionLocal() as db:
        user = db.scalar(select(AdminUser).where(AdminUser.username == username))
        if user is None or not user.is_active or user.is_deleted:
            return None
        user.last_login_at = datetime.now(UTC)
        db.commit()
        return AdminSession(
            username=user.username,
            role=user.role,
            otp_enabled=user.otp_enabled,
            is_active=user.is_active,
        )


def create_pending_otp_token(response: Response, username: str, secure: bool = True) -> None:
    settings = get_settings()
    token = _otp_serializer().dumps({"username": username})
    response.set_cookie(
        key=f"{settings.session_cookie_name}_otp",
        value=token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=300,
    )


def get_pending_otp_username(request: Request) -> str | None:
    settings = get_settings()
    token = request.cookies.get(f"{settings.session_cookie_name}_otp")
    if not token:
        return None
    try:
        data: dict[str, Any] = _otp_serializer().loads(token, max_age=300)
    except Exception:  # noqa: BLE001
        return None
    return data.get("username")


def clear_pending_otp(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(f"{settings.session_cookie_name}_otp")


def log_audit(
    action: str,
    *,
    actor: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    ip_address: str | None = None,
    details: str | None = None,
) -> None:
    try:
        with SessionLocal() as db:
            db.add(
                AuditLog(
                    actor=actor,
                    action=action,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    ip_address=ip_address,
                    details=details,
                )
            )
            db.commit()
    except Exception:  # noqa: BLE001, S110
        pass


def admin_required(func: Any) -> Any:
    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        from fastapi import Request

        request: Request | None = None
        for arg in args:
            if isinstance(arg, Request):
                request = arg
                break
        if request is None:
            request = kwargs.get("request")
        if request is None:
            raise RuntimeError("admin_required requires a Request argument")

        admin = get_current_admin(request)
        if admin is None:
            from fastapi.responses import RedirectResponse

            return RedirectResponse(url="/admin/login", status_code=303)
        kwargs["admin"] = admin
        return await func(*args, **kwargs)

    return wrapper
