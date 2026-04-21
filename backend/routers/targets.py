from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import List

from backend.database import get_db
from backend.models import User, Target
from backend import schemas, auth

router = APIRouter(prefix="/api/targets", tags=["targets"])

@router.get("/", response_model=List[schemas.TargetResponse])
async def list_targets(current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).order_by(Target.id))
    return result.scalars().all()

@router.post("/", response_model=schemas.TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(target: schemas.TargetCreate, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    # Check if exists
    result = await db.execute(select(Target).where(Target.domain == target.domain))
    if result.scalars().first():
        raise HTTPException(status_code=400, detail="Target domain already exists in inventory.")
    
    db_target = Target(**target.dict())
    db.add(db_target)
    await db.commit()
    await db.refresh(db_target)
    return db_target

@router.get("/{target_id}", response_model=schemas.TargetResponse)
async def get_target(target_id: int, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalars().first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: int, current_user: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalars().first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    
    await db.delete(target)
    await db.commit()
    return None
