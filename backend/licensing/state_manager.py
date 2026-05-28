import os
import json
import hashlib
from datetime import datetime

STATE_FILE_PATH = "/app/.license_state"

def _hash_state(state_dict: dict) -> str:
    """Creates a SHA256 hash of the state dict for integrity checking."""
    # We only hash specific keys to avoid ordering issues, and exclude the hash itself
    raw_str = f"{state_dict.get('license_id')}|{state_dict.get('consumed')}|{state_dict.get('machine_fingerprint')}|{state_dict.get('activated_at')}"
    return hashlib.sha256(raw_str.encode('utf-8')).hexdigest()

def update_state_file(license_id: str, machine_fingerprint: str, activated_at: datetime):
    """
    Writes the activation state to a persistent file to prevent database rollbacks.
    """
    state = {
        "license_id": str(license_id),
        "consumed": True,
        "machine_fingerprint": machine_fingerprint,
        "activated_at": activated_at.isoformat(),
    }
    state["hash"] = _hash_state(state)
    
    with open(STATE_FILE_PATH, "w") as f:
        json.dump(state, f, indent=4)

def get_state_file():
    """Reads the current state file."""
    if not os.path.exists(STATE_FILE_PATH):
        return None
    try:
        with open(STATE_FILE_PATH, "r") as f:
            return json.load(f)
    except:
        return None

def verify_state(db_license_id: str = None) -> bool:
    """
    Verifies that the state file matches the database. 
    If a license is activated in the DB, it must match the state file.
    If the state file exists but the DB has no license, someone rolled back the DB.
    """
    state = get_state_file()
    
    if db_license_id:
        # DB claims a license is active
        if not state:
            return False # State file is missing, tampering suspected
        
        # Verify integrity of state file
        expected_hash = _hash_state(state)
        if state.get("hash") != expected_hash:
            return False # State file tampered with
            
        # Verify it matches the DB license
        if state.get("license_id") != str(db_license_id):
            return False # DB has different license than state file
            
        return True
        
    else:
        # DB claims NO license is active
        if state and state.get("consumed"):
            return False # State file says we consumed one, DB is rolled back!
            
        return True
