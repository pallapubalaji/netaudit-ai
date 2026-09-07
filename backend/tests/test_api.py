"""
NetAudit AI - FastAPI Endpoint Unit Tests
"""

import os
from fastapi.testclient import TestClient
from backend.api.main import app

client = TestClient(app)

CISCO_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/cisco/cisco_router_01.cfg")
)
FORTINET_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/fortinet/fortigate_01.cfg")
)


def test_api_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    print("[PASS] test_api_health")


def test_api_audit_upload_cisco():
    with open(CISCO_PATH, "rb") as f:
        res = client.post("/api/audit/upload", files={"file": ("cisco_router_01.cfg", f, "text/plain")})

    assert res.status_code == 200
    data = res.json()
    assert data["vendor"] == "cisco"
    assert data["device_name"] == "Core-Edge-Router-01"
    assert data["risk"]["overall_score"] >= 75.0
    assert len(data["findings"]) > 0
    assert len(data["attack_paths"]) > 0
    print("[PASS] test_api_audit_upload_cisco")


def test_api_audit_upload_fortinet():
    with open(FORTINET_PATH, "rb") as f:
        res = client.post("/api/audit/upload", files={"file": ("fortigate_01.cfg", f, "text/plain")})

    assert res.status_code == 200
    data = res.json()
    assert data["vendor"] == "fortinet"
    assert data["device_name"] == "FW-FG100E-Edge"
    assert data["risk"]["overall_score"] >= 75.0
    print("[PASS] test_api_audit_upload_fortinet")


def test_api_simulation_endpoint():
    with open(CISCO_PATH, "r") as f:
        config_text = f.read()

    res = client.post(
        "/api/simulation/run",
        json={
            "config_text": config_text,
            "target_rule_id": "CISCO-OUTSIDE_IN-003",
            "new_source_ip_or_subnet": "192.168.1.0/24",
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert data["raw_points_reduced"] > 0.0
    assert len(data["resolved_finding_ids"]) > 0
    print("[PASS] test_api_simulation_endpoint")


if __name__ == "__main__":
    print("Running API Endpoint Tests...")
    test_api_health()
    test_api_audit_upload_cisco()
    test_api_audit_upload_fortinet()
    test_api_simulation_endpoint()
    print("\nALL API TESTS PASSED SUCCESSFULLY!")
