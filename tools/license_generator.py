#!/usr/bin/env python3
import json
import base64
import random
import string
import os
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

def generate_keypair():
    """Generates an RSA keypair and returns them as PEM encoded bytes."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    pem_priv = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_pub = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, public_key, pem_priv, pem_pub

def generate_license_key():
    """Generates a 16-character unique license key (uppercase alphanumeric with checksum)."""
    chars = string.ascii_uppercase + string.digits
    # 15 random characters
    base = ''.join(random.choice(chars) for _ in range(15))
    # 1 checksum character
    checksum = sum(ord(c) for c in base) % len(chars)
    raw_key = base + chars[checksum]
    
    # Format as XXXX-XXXX-XXXX-XXXX
    formatted_key = '-'.join(raw_key[i:i+4] for i in range(0, 16, 4))
    return raw_key, formatted_key

def generate_offline_response(private_key, payload_dict, output_file="governexa-license-response.json"):
    """Generates the offline activation response containing a signed JWT token."""
    import jwt
    import time
    
    # Ensure payload has an expiration timestamp (e.g., 1 year from now)
    if 'exp' not in payload_dict:
        payload_dict['exp'] = int(time.time()) + (365 * 24 * 60 * 60)
        
    token = jwt.encode(payload_dict, private_key, algorithm="RS256")
    
    response = {
        "license_token": token,
        "device_id": "demo-device-id"
    }
    with open(output_file, 'w') as f:
        json.dump(response, f, indent=4)
    print(f"Exported offline response to {output_file}")
    return response

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GovernExa License Module Generator")
    parser.add_argument("--generate-keys", action="store_true", help="Generate RSA keys")
    parser.add_argument("--create-license", type=str, help="Customer name to create a license for")
    parser.add_argument("--export-offline", action="store_true", help="Export offline response (requires --create-license and private_key.pem)")
    
    args = parser.parse_args()

    if args.generate_keys:
        priv, pub, pem_priv, pem_pub = generate_keypair()
        with open("private_key.pem", "wb") as f:
            f.write(pem_priv)
        with open("public_key.pem", "wb") as f:
            f.write(pem_pub)
        print("Generated private_key.pem and public_key.pem")

    if args.create_license:
        raw, formatted = generate_license_key()
        payload = {
            "customer": args.create_license,
            "license_key": formatted,
            "type": "enterprise"
        }
        print(f"Created license for {args.create_license}: {formatted}")

        if args.export_offline:
            if not os.path.exists("private_key.pem"):
                print("Error: private_key.pem not found. Run --generate-keys first.")
            else:
                with open("private_key.pem", "rb") as f:
                    private_key = f.read()
                generate_offline_response(private_key, payload)
