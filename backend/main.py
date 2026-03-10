import asyncio
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from fastapi.security import OAuth2PasswordRequestForm

from backend.database import engine, Base, get_db, AsyncSessionLocal
from backend.models import User, Scan
from backend import schemas, auth
from backend.routers import scans, admin, dashboard, websockets

app = FastAPI(title="Eartheye API")

app.include_router(scans.router)
app.include_router(admin.router)
app.include_router(dashboard.router)
app.include_router(websockets.router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    # Auto-create tables for local testing
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        
    # Ensure default admin exists
    async with AsyncSessionLocal() as db:
        admin_email = "Okechuwkujoel44@gmail.com"
        result = await db.execute(select(User).where(User.email == admin_email))
        admin = result.scalars().first()
        if not admin:
            print("Creating default admin account...")
            hashed_pw = auth.get_password_hash("Scientist44@")
            new_admin = User(email=admin_email, password_hash=hashed_pw, role="Admin")
            db.add(new_admin)
            await db.commit()

@app.post("/api/auth/register", response_model=schemas.UserResponse)
async def register(user: schemas.UserCreate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == user.email))
    db_user = result.scalars().first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = auth.get_password_hash(user.password)
    # Give Admin role if default admin email is used
    role = "Admin" if user.email.lower() == "okechuwkujoel44@gmail.com".lower() else "User"
    
    new_user = User(email=user.email, password_hash=hashed_password, role=role)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

@app.post("/api/auth/login", response_model=schemas.Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == form_data.username))
    user = result.scalars().first()
    if not user or not auth.verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    access_token_expires = auth.timedelta(minutes=auth.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/users/me", response_model=schemas.UserResponse)
async def read_users_me(current_user: User = Depends(auth.get_current_user)):
    return current_user
