"""Client-facing license API for the desktop application."""
from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.crypto import hash_key, load_private_key, sign_payload
from app.database import SessionLocal
from app.models import Installation, LicenseActivation, LicenseKey, LockOrder, Release

router = APIRouter(prefix="/api")


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_private_key() -> Ed25519PrivateKey:
    settings = get_settings()
    return load_private_key(settings.keys_dir / "private.pem")


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #


class SyncRequest(BaseModel):
    installation_id: str = Field(..., min_length=1, max_length=128)
    license_key: str = Field(default="", max_length=128)
    machine_fingerprint: str = Field(..., min_length=1, max_length=256)
    app_version: str | None = Field(default=None, max_length=64)
    platform: str | None = Field(default=None, max_length=64)


class SyncResponse(BaseModel):
    status: str
    server_timestamp: str
    offline_until: str
    pending_orders: list[dict[str, Any]]
    release: dict[str, Any] | None = None
    signature: str


class HeartbeatRequest(BaseModel):
    installation_id: str = Field(..., min_length=1, max_length=128)
    machine_fingerprint: str = Field(..., min_length=1, max_length=256)
    app_version: str | None = Field(default=None, max_length=64)


class HeartbeatResponse(BaseModel):
    status: str
    server_timestamp: str
    locked: bool


class UpdateCheckResponse(BaseModel):
    version: str | None = None
    download_url: str | None = None
    checksum_sha256: str | None = None
    changelog: str | None = None
    mandatory: bool = False


class AckRequest(BaseModel):
    installation_id: str = Field(..., min_length=1, max_length=128)
    order_id: str | None = None
    order_ids: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _upsert_installation(
    db: Session,
    installation_id: str,
    machine_fingerprint: str,
    app_version: str | None,
    platform: str | None,
) -> Installation:
    inst = db.scalar(select(Installation).where(Installation.installation_id == installation_id))
    now = datetime.now(UTC)
    if inst is None:
        inst = Installation(
            installation_id=installation_id,
            machine_fingerprint=machine_fingerprint,
            app_version=app_version,
            platform=platform,
            first_seen_at=now,
        )
        db.add(inst)
    else:
        inst.machine_fingerprint = machine_fingerprint
        if app_version:
            inst.app_version = app_version
        if platform:
            inst.platform = platform
    inst.last_seen_at = now
    db.commit()
    db.refresh(inst)
    return inst


def _build_pending_orders(db: Session, installation_id: str) -> list[dict[str, Any]]:
    orders = db.scalars(
        select(LockOrder).where(
            LockOrder.installation_id == installation_id,
            LockOrder.delivered_at.is_(None),
        )
    ).all()
    return [{"id": str(o.id), "type": o.order_type, "reason": o.reason or ""} for o in orders]


def _get_latest_release(db: Session) -> Release | None:
    return db.scalar(
        select(Release)
        .where(Release.revoked_at.is_(None), Release.is_deleted == False)
        .order_by(Release.published_at.desc())
        .limit(1)
    )


def _utc_now() -> datetime:
    now = datetime.now(UTC)
    return now.replace(tzinfo=None) if now.tzinfo else now


def _normalize_dt(value: datetime | None) -> datetime:
    if value is None:
        raise ValueError("expected a datetime value")
    return value.replace(tzinfo=None) if value.tzinfo else value


def _key_expired(key: LicenseKey) -> bool:
    if key.expires_at is None:
        return False
    return _utc_now() >= _normalize_dt(key.expires_at)


def _offline_until(key: LicenseKey) -> datetime:
    now = _utc_now()
    grace = now + timedelta(days=key.offline_grace_days)
    if key.expires_at is None:
        return grace
    return min(grace, _normalize_dt(key.expires_at))


# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #


@router.post("/license/sync", response_model=SyncResponse)
def sync_license(
    request: Request,
    req: SyncRequest,
    db: Session = Depends(get_db),  # noqa: B008
    private_key: Any = Depends(get_private_key),  # noqa: B008
) -> SyncResponse:
    inst = _upsert_installation(db, req.installation_id, req.machine_fingerprint, req.app_version, req.platform)

    status_val = "no_key"
    offline_until = datetime.now(UTC)
    key = None

    # Look up the installation's current active activation if no key provided.
    if not req.license_key:
        existing_activation = db.scalar(
            select(LicenseActivation).where(
                LicenseActivation.installation_id == req.installation_id,
                LicenseActivation.machine_fingerprint == req.machine_fingerprint,
                LicenseActivation.status == "active",
            )
        )
        if existing_activation:
            key = db.get(LicenseKey, existing_activation.license_key_id)
            if key:
                if key.revoked:
                    status_val = "revoked"
                elif _key_expired(key):
                    status_val = "expired"
                else:
                    status_val = "active"
                    offline_until = _offline_until(key)

    if req.license_key:
        key_hash = hash_key(req.license_key)
        key = db.scalar(select(LicenseKey).where(LicenseKey.key_hash == key_hash, LicenseKey.is_deleted == False))

        if not key:
            status_val = "invalid_key"
        elif key.revoked:
            status_val = "revoked"
        elif _key_expired(key):
            status_val = "expired"
        else:
            existing = db.scalar(
                select(LicenseActivation).where(
                    LicenseActivation.license_key_id == key.id,
                    LicenseActivation.installation_id == req.installation_id,
                    LicenseActivation.machine_fingerprint == req.machine_fingerprint,
                    LicenseActivation.status == "active",
                )
            )
            if existing:
                # refresh activation link
                inst.license_key_id = key.id
                status_val = "active"
                offline_until = _offline_until(key)
            elif key.activation_count >= key.activation_limit:
                status_val = "limit_exceeded"
            else:
                # check cross-machine
                other = db.scalar(
                    select(LicenseActivation).where(
                        LicenseActivation.license_key_id == key.id,
                        LicenseActivation.status == "active",
                    )
                )
                if other and key.activation_limit <= 1:
                    status_val = "invalid_hwid"
                else:
                    activation = LicenseActivation(
                        license_key_id=key.id,
                        installation_id=req.installation_id,
                        machine_fingerprint=req.machine_fingerprint,
                        status="active",
                    )
                    db.add(activation)
                    key.activation_count += 1
                    inst.license_key_id = key.id
                    status_val = "active"
                    offline_until = _offline_until(key)
                    db.commit()

    # Deleted installations are retained for audit but cannot run.
    if inst.is_deleted or inst.locked:
        status_val = "locked"

    pending_orders = _build_pending_orders(db, req.installation_id)

    latest = _get_latest_release(db)
    release_payload = None
    if latest:
        release_payload = {
            "version": latest.version,
            "download_url": latest.download_url,
            "checksum_sha256": latest.checksum_sha256,
            "changelog": latest.changelog,
            "mandatory": latest.is_mandatory,
        }

    server_timestamp = datetime.now(UTC).isoformat()
    response_core: dict[str, Any] = {
        "status": status_val,
        "server_timestamp": server_timestamp,
        "offline_until": offline_until.isoformat(),
        "pending_orders": pending_orders,
    }
    if release_payload:
        response_core["release"] = release_payload

    signature = sign_payload(private_key, response_core)

    return SyncResponse(
        status=status_val,
        server_timestamp=server_timestamp,
        offline_until=offline_until.isoformat(),
        pending_orders=pending_orders,
        release=release_payload,
        signature=signature,
    )


@router.post("/license/ack")
def ack_order(req: AckRequest, db: Session = Depends(get_db)) -> dict[str, str]:
    now = datetime.now(UTC)
    order_ids = list(req.order_ids)
    if req.order_id:
        order_ids.append(req.order_id)
    for order_id in order_ids:
        if order_id.startswith("direct_status_"):
            continue
        order = db.scalar(
            select(LockOrder).where(
                LockOrder.installation_id == req.installation_id,
                LockOrder.id == order_id,
            )
        )
        if order:
            order.delivered_at = now
    db.commit()
    return {"status": "acknowledged"}


@router.post("/license/heartbeat", response_model=HeartbeatResponse)
def heartbeat(req: HeartbeatRequest, db: Session = Depends(get_db)) -> HeartbeatResponse:
    inst = db.scalar(select(Installation).where(Installation.installation_id == req.installation_id))
    now = datetime.now(UTC)
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="installation_not_found")
    inst.last_heartbeat_at = now
    inst.last_seen_at = now
    if req.app_version:
        inst.app_version = req.app_version
    db.commit()
    return HeartbeatResponse(
        status="ok",
        server_timestamp=now.isoformat(),
        locked=inst.locked,
    )


@router.get("/updates/check")
def check_updates(
    installation_id: str,
    current_version: str | None = None,
    db: Session = Depends(get_db),
) -> UpdateCheckResponse:
    inst = db.scalar(select(Installation).where(Installation.installation_id == installation_id))
    if inst is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="installation_not_found")

    latest = _get_latest_release(db)
    if latest is None:
        return UpdateCheckResponse()

    return UpdateCheckResponse(
        version=latest.version,
        download_url=latest.download_url,
        checksum_sha256=latest.checksum_sha256,
        changelog=latest.changelog,
        mandatory=latest.is_mandatory,
    )
