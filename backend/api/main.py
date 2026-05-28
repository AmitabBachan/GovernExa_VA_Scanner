from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from auth.security import create_access_token, verify_password
from api.routers import scan, devices, vulnerabilities, reports, dashboard, users, settings, credentials, backup

app = FastAPI(
    title="VulnScope Enterprise API",
    version="1.1.0"
)

# CORS middleware for Frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Update for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(scan.router)
app.include_router(devices.router)
app.include_router(vulnerabilities.router)
app.include_router(reports.router)
app.include_router(dashboard.router)
app.include_router(users.router)
app.include_router(settings.router)
app.include_router(backup.router)
app.include_router(credentials.router, prefix="/credentials", tags=["Credentials"])

from licensing.router import router as licensing_router
app.include_router(licensing_router)

@app.post("/api/auth/login", tags=["Authentication"])
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Stub: single admin user. In production, look up user from DB.
    USERS = {
        "admin": {"password": "password", "role": "admin"},
        "operator": {"password": "operator123", "role": "operator"},
        "viewer": {"password": "viewer123", "role": "viewer"},
    }
    user = USERS.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    # Embed role in the token so RBAC can decode it
    access_token = create_access_token(subject={"sub": form_data.username, "role": user["role"]})
    return {"access_token": access_token, "token_type": "bearer", "role": user["role"]}

@app.get("/api/health", tags=["System"])
def health_check():
    return {"status": "ok", "services": {"database": "up", "celery": "up"}}
