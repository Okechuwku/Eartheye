from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List

from backend.database import get_db
from backend.models import User, Scan
from backend import schemas, auth

router = APIRouter(prefix="/api/admin", tags=["admin"])

@router.get("/users", response_model=List[schemas.UserResponse])
async def list_all_users(admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User))
    return result.scalars().all()

@router.get("/scans", response_model=List[schemas.ScanResponse])
async def list_all_scans(admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan))
    return result.scalars().all()
