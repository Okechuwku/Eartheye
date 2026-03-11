import asyncio
import os

from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from fastapi.security import OAuth2PasswordRequestForm
from starlette.middleware.trustedhost import TrustedHostMiddleware

from backend.database import engine, Base, get_db, AsyncSessionLocal
from backend.models import User, Scan
from backend import schemas, auth
from backend.routers import scans, admin, dashboard, websockets
from backend.security import build_rate_limit_key, rate_limiter
from backend.services.automation import automation_worker
from backend.services.schema_sync import ensure_runtime_schema
from backend.services.subscriptions import normalize_role, subscription_plan_for_role

DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL", "okechuwkujoel44@gmail.com").strip().lower()
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", "Scientist44@").strip()
CORS_ORIGINS = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",") if origin.strip()]
ALLOWED_HOSTS = [host.strip() for host in os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1,eartheye.me,www.eartheye.me,api.eartheye.me").split(",") if host.strip()]

RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_GLOBAL_REQUESTS = int(os.getenv("RATE_LIMIT_GLOBAL_REQUESTS", "240"))
RATE_LIMIT_AUTH_REQUESTS = int(os.getenv("RATE_LIMIT_AUTH_REQUESTS", "20"))
RATE_LIMIT_SCAN_CREATE_REQUESTS = int(os.getenv("RATE_LIMIT_SCAN_CREATE_REQUESTS", "10"))
RATE_LIMIT_DISABLED = os.getenv("RATE_LIMIT_DISABLED", "false").strip().lower() == "true"

app = FastAPI(title="Eartheye API")

app.include_router(scans.router)
app.include_router(admin.router)
app.include_router(dashboard.router)
app.include_router(websockets.router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS else ["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept", "Origin"],
)

app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS if ALLOWED_HOSTS else ["*"],
)


@app.middleware("http")
async def enforce_rate_limits(request: Request, call_next):
    if RATE_LIMIT_DISABLED:
        return await call_next(request)

    path = request.url.path
    if path.startswith("/docs") or path.startswith("/redoc") or path.startswith("/openapi"):
        return await call_next(request)

    bucket = "global"
    limit = RATE_LIMIT_GLOBAL_REQUESTS

    if path.startswith("/api/auth/"):
        bucket = "auth"
        limit = RATE_LIMIT_AUTH_REQUESTS
    elif request.method.upper() == "POST" and path == "/api/scans/":
        bucket = "scan_create"
        limit = RATE_LIMIT_SCAN_CREATE_REQUESTS

    key = build_rate_limit_key(request, bucket)
    allowed, retry_after = await rate_limiter.check(key, limit, RATE_LIMIT_WINDOW_SECONDS)
    if not allowed:
        return JSONResponse(
            status_code=429,
            content={"detail": "Rate limit exceeded. Please retry shortly."},
            headers={"Retry-After": str(retry_after)},
        )

    return await call_next(request)

@app.on_event("startup")
async def startup():
    # Auto-create tables for local testing
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await ensure_runtime_schema(conn)
        
    # Ensure default admin exists
    async with AsyncSessionLocal() as db:
        admin_email = DEFAULT_ADMIN_EMAIL
        result = await db.execute(select(User).where(func.lower(User.email) == admin_email))
        admin = result.scalars().first()
        if not admin:
            print("Creating default admin account...")
            hashed_pw = auth.get_password_hash(DEFAULT_ADMIN_PASSWORD)
            new_admin = User(
                email=admin_email,
                password_hash=hashed_pw,
                role="Administrator",
                subscription_plan="Administrator",
                subscription_status="active",
            )
            db.add(new_admin)
        else:
            admin.role = "Administrator"
            admin.subscription_plan = "Administrator"
            admin.subscription_status = admin.subscription_status or "active"

        users_result = await db.execute(select(User))
        for user in users_result.scalars().all():
            normalized_role = normalize_role(user.role)
            user.role = normalized_role
            user.subscription_plan = subscription_plan_for_role(normalized_role)
            user.subscription_status = user.subscription_status or "active"

        await db.commit()

    automation_worker.start()


@app.on_event("shutdown")
async def shutdown():
    await automation_worker.stop()

@app.post("/api/auth/register", response_model=schemas.UserResponse)
async def register(user: schemas.UserCreate, db: AsyncSession = Depends(get_db)):
    normalized_email = user.email.strip().lower()
    result = await db.execute(select(User).where(func.lower(User.email) == normalized_email))
    db_user = result.scalars().first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = auth.get_password_hash(user.password)
    # Give Admin role if default admin email is used
    role = "Administrator" if normalized_email == DEFAULT_ADMIN_EMAIL else "Free"
    
    new_user = User(
        email=normalized_email,
        password_hash=hashed_password,
        role=role,
        subscription_plan=subscription_plan_for_role(role),
        subscription_status="active",
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

@app.post("/api/auth/login", response_model=schemas.Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    normalized_email = form_data.username.strip().lower()
    result = await db.execute(select(User).where(func.lower(User.email) == normalized_email))
    user = result.scalars().first()
    if not user or not auth.verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token_expires = auth.timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": normalized_email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/users/me", response_model=schemas.UserResponse)
async def read_users_me(current_user: User = Depends(auth.get_current_user)):
    return current_user
