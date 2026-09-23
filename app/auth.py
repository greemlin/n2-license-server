"""Session-based admin authentication."""
from __future__ import annotations

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


class _AdminSession:
    def __init__(self, username: str, is_active: bool = True) -> None:
        self.username = username
        self.is_active = is_active


def get_current_admin(request: Request) -> _AdminSession | None:
    settings = get_settings()
    token = request.cookies.get(settings.session_cookie_name)
    if not token:
        return None
    try:
        data = _serializer().loads(token, max_age=settings.session_max_age_seconds)
    except Exception:  # noqa: BLE001
        return None
    username = data.get("username")
    if not username or username != settings.admin_username:
        return None
    # Ensure an admin row exists for audit/metadata purposes.
    with SessionLocal() as db:
        user = db.scalar(select(AdminUser).where(AdminUser.username == username))
        if user is None:
            user = AdminUser(username=username, password_hash=settings.admin_password_hash)
            db.add(user)
            db.commit()
        elif not user.is_active:
            return None
        user.last_login_at = datetime.now(UTC)
        db.commit()
    return _AdminSession(username=username, is_active=True)


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
