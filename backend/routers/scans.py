from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func
from typing import List
from datetime import datetime
import re

from backend.database import get_db
from backend.models import Scan, User
from backend import schemas, auth
from backend.services.scanner import trigger_scan_task

router = APIRouter(prefix="/api/scans", tags=["scans"])

# Basic regex for a valid hostname / domain
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$"
)

@router.post("/", response_model=schemas.ScanResponse)
async def create_scan(scan_in: schemas.ScanCreate, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    # 1. Domain Validation
    target = scan_in.target_domain.strip().lower()
    if target.startswith("http://") or target.startswith("https://"):
        target = target.split("://")[1].split("/")[0]
        
    if not DOMAIN_REGEX.match(target):
        raise HTTPException(status_code=400, detail="Invalid domain format. Please provide a valid hostname (e.g., example.com)")

    # 2. Rate Limiting / Scan Limits
    result = await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == current_user.id, Scan.status.in_(["Pending", "Running"]))
    )
    active_count = result.scalar() or 0
    if active_count >= 3:
        raise HTTPException(status_code=429, detail="Maximum concurrent scan limit reached. Please wait for active operations to complete.")

    new_scan = Scan(
        user_id=current_user.id,
        target_domain=target,
        scan_type=scan_in.scan_type,
        status="Pending",
        created_at=datetime.utcnow()
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    trigger_scan_task(new_scan.id, target, scan_in.scan_type)
    return new_scan

@router.get("/", response_model=List[schemas.ScanResponse])
async def list_scans(current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()))
    return result.scalars().all()

@router.get("/{scan_id}", response_model=schemas.ScanResponse)
async def get_scan(scan_id: int, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id and current_user.role != "Admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return scan
