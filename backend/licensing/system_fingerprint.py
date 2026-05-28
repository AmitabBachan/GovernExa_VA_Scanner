import uuid
import hashlib
import platform
import os

def get_machine_fingerprint() -> str:
    """
    Generates a stable machine fingerprint to bind the license to this specific installation.
    Uses MAC address, architecture, and OS details to create a unique hash.
    """
    try:
        # Get MAC address (stable across reboots for most bare metal/VMs, might change in some ephemeral containers 
        # but since GovernExa backend usually runs on a single host docker-compose, we can use the node ID)
        mac_num = uuid.getnode()
        mac = ':'.join(("%012X" % mac_num)[i:i+2] for i in range(0, 12, 2))
        
        # Get OS architecture and system
        system = platform.system()
        machine = platform.machine()
        
        # Get machine ID if available (Linux)
        machine_id = ""
        if os.path.exists("/etc/machine-id"):
            with open("/etc/machine-id", "r") as f:
                machine_id = f.read().strip()
                
        # Combine factors
        raw_fingerprint = f"{mac}-{system}-{machine}-{machine_id}"
        
        # Hash to create a clean, uniform fingerprint string
        fingerprint_hash = hashlib.sha256(raw_fingerprint.encode('utf-8')).hexdigest()
        
        # Format as GX-MACH-[hash prefix]
        return f"GX-MACH-{fingerprint_hash[:16].upper()}"
        
    except Exception as e:
        # Fallback if something fails, though this should be completely stable
        return "GX-MACH-UNKNOWN-0000000000"
