import os
import sys
import time
import jwt
import uuid
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

# Add the parent tools directory to sys.path so we can import license_generator
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import license_generator

app = FastAPI(title="Vendor License Portal")

# Serve the static UI files
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

SECRET_KEY = "SUPER_SECRET_VENDOR_PORTAL_KEY_DO_NOT_SHARE"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# Hardcoded Vendor Credentials for internal use
VENDOR_USERNAME = "vendor_admin"
VENDOR_PASSWORD = "vendor_password123!"

class GenerateRequest(BaseModel):
    customer_name: str
    tier: str
    validity_days: int
    features: list[str]
    machine_fingerprint: str

def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": time.time() + (24 * 60 * 60)}) # 1 day expiration
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") != VENDOR_USERNAME:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

@app.get("/")
def read_index():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.post("/api/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != VENDOR_USERNAME or form_data.password != VENDOR_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/generate")
def generate_license(req: GenerateRequest, current_user: dict = Depends(verify_token)):
    # 1. Ensure private key exists
    key_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'private_key.pem'))
    if not os.path.exists(key_path):
        raise HTTPException(status_code=500, detail="private_key.pem not found in tools directory. Generate keys first.")
        
    with open(key_path, "rb") as f:
        private_key = f.read()
        
    # 2. Generate unique key
    raw_key, formatted_key = license_generator.generate_license_key()
    
    # 3. Build payload
    payload = {
        "license_id": str(uuid.uuid4()),
        "machine_fingerprint": req.machine_fingerprint,
        "customer_name": req.customer_name,
        "license_key": formatted_key,
        "tier": req.tier,
        "features": req.features,
        "validity_days": req.validity_days,
        "exp": int(time.time()) + (5 * 365 * 24 * 60 * 60) # 5 years to activate
    }
    
    # 4. Sign payload using generator function
    response = license_generator.generate_offline_response(private_key, payload, output_file=os.devnull)
    
    # Return the data to the frontend so it can trigger a download
    return {
        "license_key": formatted_key,
        "offline_response": response
    }
