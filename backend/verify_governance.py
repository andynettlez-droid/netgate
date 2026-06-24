import urllib.request
import json
import sys

API_BASE = "http://localhost:8000"

def test_endpoint(payload):
    req = urllib.request.Request(
        f"{API_BASE}/api/approve",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, json.loads(res.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {"detail": e.reason}

def run_tests():
    print("=== Testing Role-Based Action Gating & Multi-Sig Releases ===")
    
    mock_configs = {"TEST-RT01": "hostname TEST-RT01\n!"}
    
    # Test 1: No signatures
    print("\n[Test 1] Submitting approval with empty signatures...")
    payload_empty = {
        "signatures": [],
        "comment": "Testing governance audit checks",
        "configs": mock_configs
    }
    code, data = test_endpoint(payload_empty)
    print(f"Response Code: {code}")
    print(f"Response Body: {data}")
    assert code == 400, "Expected 400 bad request for empty signatures"
    assert "required" in data.get("detail", ""), "Expected detail message indicating signatures are required"
    print(">>> PASS: Empty signatures rejected successfully.")

    # Test 2: Incomplete signatures (Auditor only)
    print("\n[Test 2] Submitting approval with Auditor signature only...")
    payload_auditor_only = {
        "signatures": [{"name": "Marcus Vance", "role": "Security Auditor"}],
        "comment": "Testing auditor only signature",
        "configs": mock_configs
    }
    code, data = test_endpoint(payload_auditor_only)
    print(f"Response Code: {code}")
    print(f"Response Body: {data}")
    assert code == 400, "Expected 400 bad request for Auditor-only signature"
    assert "required" in data.get("detail", ""), "Expected detail message indicating Release Manager signature is also required"
    print(">>> PASS: Auditor-only signature rejected successfully.")

    # Test 3: Incomplete signatures (Manager only)
    print("\n[Test 3] Submitting approval with Release Manager signature only...")
    payload_manager_only = {
        "signatures": [{"name": "Andrew Nettleton", "role": "Release Manager"}],
        "comment": "Testing manager only signature",
        "configs": mock_configs
    }
    code, data = test_endpoint(payload_manager_only)
    print(f"Response Code: {code}")
    print(f"Response Body: {data}")
    assert code == 400, "Expected 400 bad request for Manager-only signature"
    assert "required" in data.get("detail", ""), "Expected detail message indicating Security Auditor signature is also required"
    print(">>> PASS: Manager-only signature rejected successfully.")

    # Test 4: Both signatures (Success)
    print("\n[Test 4] Submitting approval with BOTH signatures...")
    payload_both = {
        "signatures": [
            {"name": "Marcus Vance", "role": "Security Auditor"},
            {"name": "Andrew Nettleton", "role": "Release Manager"}
        ],
        "comment": "Co-signed by Auditor and Manager.",
        "configs": mock_configs
    }
    code, data = test_endpoint(payload_both)
    print(f"Response Code: {code}")
    print(f"Response Body: {data}")
    assert code == 200, "Expected 200 OK for full signatures"
    assert data.get("status") == "success", "Expected success status in response"
    print(">>> PASS: Multi-signature release committed successfully.")
    
    # Test 5: Verify entry in history ledger
    print("\n[Test 5] Fetching history ledger to verify entry insertion...")
    history_req = urllib.request.Request(f"{API_BASE}/api/history", method="GET")
    try:
        with urllib.request.urlopen(history_req) as res:
            history_data = json.loads(res.read().decode("utf-8"))
            latest = history_data[0]
            print(f"Latest entry: {latest['approver']} - {latest['comment']}")
            assert len(latest["signatures"]) == 2, "Expected 2 signatures in history entry"
            print(">>> PASS: Verified audit log record matches request.")
    except Exception as e:
        print(f"Failed to verify history: {e}")
        sys.exit(1)
        
    print("\nSUCCESS: ALL GOVERNANCE AND RBAC VALIDATIONS PASSED!")

if __name__ == "__main__":
    run_tests()
