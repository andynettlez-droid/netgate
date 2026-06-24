import json
import hashlib
import requests
import copy
import os

BASE_URL = "http://localhost:8000"
AUDIT_FILE = "approval_audit_trail.json"

def run_verification():
    print("--- NetGate Cryptographic Ledger Verification ---")
    
    print("\n[1] Fetching ledger integrity from API...")
    try:
        res = requests.get(f"{BASE_URL}/api/ledger/verify")
        data = res.json()
        print(f"    Status: {data['is_valid']} | {data['message']}")
    except Exception as e:
        print(f"    Failed to contact API: {e}")
        print("    Ensure the backend server is running on port 8000.")
        return

    print("\n[2] Performing manual cryptographic tamper test...")
    if not os.path.exists(AUDIT_FILE):
        print(f"    {AUDIT_FILE} does not exist yet. Please submit an approval first.")
        return
        
    try:
        with open(AUDIT_FILE, "r") as f:
            trail = json.load(f)
    except Exception as e:
        print(f"    Failed to load {AUDIT_FILE}: {e}")
        return

    if not trail:
        print("    Ledger is empty. Please submit an approval through the UI first to test tampering.")
        return

    # Tamper with the most recent entry (index 0)
    print("    Tampering with the latest entry (changing comment to 'BACKDOOR')...")
    original_trail = copy.deepcopy(trail)
    trail[0]["comment"] = "BACKDOOR INSTALLED"
    
    with open(AUDIT_FILE, "w") as f:
        json.dump(trail, f, indent=4)

    print("\n[3] Re-verifying ledger integrity after tampering...")
    try:
        res = requests.get(f"{BASE_URL}/api/ledger/verify")
        data = res.json()
        print(f"    Status: {data['is_valid']} | {data['message']}")
        if not data["is_valid"]:
            print("    [SUCCESS] Tampering was correctly caught by the cryptographic hash chain!")
        else:
            print("    [FAILURE] Tampering was NOT detected. Hash validation is broken.")
    except Exception as e:
        print(f"    Failed to contact API: {e}")

    print("\n[4] Restoring original ledger...")
    with open(AUDIT_FILE, "w") as f:
        json.dump(original_trail, f, indent=4)
    print("    Ledger restored to mathematically valid state.")

if __name__ == "__main__":
    run_verification()
