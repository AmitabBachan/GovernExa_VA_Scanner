import jwt
from datetime import datetime

# In a production environment, the public key should be loaded from a secure vault or file
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu4K8HgBZJL22UJxZwo+Q
iEF2wrSOIO0xPLa8YsyJPoEpNaLliaasqTlb5IjUog2ZEaVT3gUVDeYyJkeUKRI/
XcOISYJBRCXDeIvXSJooUjhIhuKwUI3cuw2Nti0oQRrPaTvo78SP3fkyKhD8nBds
PMFj4zSa4l7oPOBusaE+wELhFZ3gY/Do+1FoYOHqCTRm4GpNLAnEsy7OQHQLCAV5
T87oHmR4+esVwhm8nGpP9Y9bJqXS+zF3+gmi8i+QeRSxmQBDDlPvtKZg8t59dboK
KUkzQEYZIHPC9SklWSLLw2c86g03VtE0hcNBTaAiCVA1foGEGqCn+UG+EoC/VSQ0
9wIDAQAB
-----END PUBLIC KEY-----"""

def verify_license_token(token: str) -> dict:
    """
    Verifies the JWT RSA signature of the license token.
    Returns the decoded payload if valid. Raises an exception if invalid or expired.
    """
    try:
        # Decode using the public key and RS256 algorithm
        # jwt.decode verifies signature and standard claims like 'exp' if present
        decoded = jwt.decode(token, PUBLIC_KEY_PEM, algorithms=["RS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        raise ValueError("License token has expired.")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid license signature: {str(e)}")

def is_license_active(expires_at: datetime) -> bool:
    """
    Check if a given expiration datetime is still in the future.
    """
    if not expires_at:
        return False # Or True if you want to support perpetual licenses, assuming False for safety
    return datetime.utcnow() < expires_at
