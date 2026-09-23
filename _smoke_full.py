"""Full smoke test for N2 License Server admin + client API."""
import re
import uuid

import bcrypt
from fastapi.testclient import TestClient

from app.config import get_settings
from app.database import init_engine
from app.main import app

s = get_settings()
s.admin_password_hash = bcrypt.hashpw(b"demo1234", bcrypt.gensalt(rounds=12)).decode()
s.secret_key = "test-secret-key-for-local-smoke-32bytes"
init_engine(s)

installation_id = f"smoke-{uuid.uuid4().hex[:8]}"

with TestClient(app) as client:
    # 1. Admin login
    r = client.post("/admin/login", data={"username": "admin", "password": "demo1234"}, follow_redirects=False)
    assert r.status_code == 303 and "n2ls_session" in r.headers.get("set-cookie", "")
    print("[OK] admin login")

    # 2. Dashboard
    r = client.get("/admin/", cookies=r.cookies)
    assert r.status_code == 200
    print("[OK] dashboard")

    # 3. Create key
    r = client.post(
        "/admin/keys",
        data={"edition": "standard", "activation_limit": 1, "offline_grace_days": 10, "label": "Smoke", "note": ""},
        follow_redirects=False,
    )
    assert r.status_code == 303
    key_url = r.headers["location"]
    key_id = key_url.split("/")[-1]
    r = client.get(key_url)
    assert r.status_code == 200
    match = re.search(r"THAL-[A-Z0-9-]+", r.text)
    assert match
    key_text = match.group(0)
    print("[OK] create key", key_text)

    # 4. Client sync activates installation
    r = client.post(
        "/api/license/sync",
        json={
            "installation_id": installation_id,
            "license_key": key_text,
            "machine_fingerprint": "fp-001",
            "app_version": "1.0.0",
            "platform": "windows",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "active"
    assert body["offline_until"]
    assert body["signature"]
    print("[OK] sync activate")

    # 5. Admin locks installation
    r = client.post(
        f"/admin/installations/{installation_id}/lock",
        data={"reason": "smoke test lock"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    print("[OK] admin lock")

    # 6. Client receives lock order
    r = client.post(
        "/api/license/sync",
        json={
            "installation_id": installation_id,
            "license_key": key_text,
            "machine_fingerprint": "fp-001",
            "app_version": "1.0.0",
            "platform": "windows",
        },
    )
    body = r.json()
    assert body["status"] == "locked"
    assert any(o["type"] == "lock" for o in body["pending_orders"])
    order_id = body["pending_orders"][0]["id"]
    print("[OK] sync locked, order", order_id)

    # 7. Ack order
    r = client.post("/api/license/ack", json={"installation_id": installation_id, "order_ids": [order_id]})
    print("ack status", r.status_code, r.text[:300])
    assert r.status_code == 200
    print("[OK] ack order")

    # 8. Admin unlocks installation
    r = client.post(
        f"/admin/installations/{installation_id}/unlock",
        data={"reason": "smoke test unlock"},
        follow_redirects=False,
    )
    print("unlock status", r.status_code, r.text[:500])
    assert r.status_code == 200
    print("[OK] admin unlock")

    # 9. Client sync is active again
    r = client.post(
        "/api/license/sync",
        json={
            "installation_id": installation_id,
            "license_key": key_text,
            "machine_fingerprint": "fp-001",
            "app_version": "1.0.0",
            "platform": "windows",
        },
    )
    body = r.json()
    assert body["status"] == "active"
    print("[OK] sync active after unlock")

    # 10. Admin revokes key
    r = client.post(f"/admin/keys/{key_id}/revoke", follow_redirects=False)
    assert r.status_code == 303
    print("[OK] revoke key")

    # 11. Client sync shows revoked
    r = client.post(
        "/api/license/sync",
        json={
            "installation_id": installation_id,
            "license_key": key_text,
            "machine_fingerprint": "fp-001",
            "app_version": "1.0.0",
            "platform": "windows",
        },
    )
    body = r.json()
    print("revoke sync body", body)
    assert body["status"] in ("revoked", "locked")
    print("[OK] sync revoked/locked")

print("\nALL SMOKE TESTS PASSED")
