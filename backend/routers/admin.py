from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func
from typing import List

from backend.database import get_db
from backend.models import User, Scan, Vulnerability
from backend import schemas, auth
import logging

router = APIRouter(prefix="/api/admin", tags=["admin"])
logger = logging.getLogger("admin_audit")


@router.get("/overview", response_model=schemas.AdminOverviewResponse)
async def admin_overview(admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    total_users = (await db.execute(select(func.count(User.id)))).scalar() or 0
    total_scans = (await db.execute(select(func.count(Scan.id)))).scalar() or 0
    total_vulns = (await db.execute(select(func.count(Vulnerability.id)))).scalar() or 0
    total_secrets = (await db.execute(select(func.count(SecretFinding.id)))).scalar() or 0
    premium_users = (
        await db.execute(select(func.count(User.id)).where(User.role.in_(["Premium", "Administrator", "Admin"])))
    ).scalar() or 0
    active_monitors = (
        await db.execute(select(func.count(MonitoringTarget.id)).where(MonitoringTarget.enabled.is_(True)))
    ).scalar() or 0
    return {
        "total_users": total_users,
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns,
        "total_secrets": total_secrets,
        "premium_users": premium_users,
        "active_monitors": active_monitors,
    }


@router.get("/users", response_model=List[schemas.UserResponse])
async def list_all_users(admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).order_by(User.id))
    return result.scalars().all()


@router.patch("/users/{user_id}/tier", response_model=schemas.UserResponse)
async def update_user_tier(
    user_id: int, 
    update: schemas.UserTierUpdate, 
    admin: User = Depends(auth.get_current_admin), 
    db: AsyncSession = Depends(get_db)
):
    if update.subscription_tier not in ["Free", "Premium"]:
        raise HTTPException(status_code=400, detail="Invalid tier. Must be Free or Premium")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    old_tier = user.subscription_tier
    user.subscription_tier = update.subscription_tier
    await db.commit()
    await db.refresh(user)
    
    # Audit log
    logger.warning(f"AUDIT | Admin {admin.email} changed tier for {user.email}: {old_tier} -> {user.subscription_tier}")
    
    return user


@router.patch("/users/{user_id}/role", response_model=schemas.UserResponse)
async def update_user_role(
    user_id: int, 
    update: schemas.UserRoleUpdate, 
    admin: User = Depends(auth.get_current_admin), 
    db: AsyncSession = Depends(get_db)
):
    if update.role not in ["Admin", "User"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be Admin or User")

    if user_id == admin.id and update.role == "User":
        raise HTTPException(status_code=400, detail="Cannot demote yourself.")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    old_role = user.role
    user.role = update.role
    await db.commit()
    await db.refresh(user)
    
    logger.warning(f"AUDIT | Admin {admin.email} changed role for {user.email}: {old_role} -> {user.role}")
    
    return user


@router.get("/scans", response_model=List[schemas.ScanResponse])
async def list_all_scans(admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return result.scalars().all()


@router.delete("/scans/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: int, 
    admin: User = Depends(auth.get_current_admin), 
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    await db.delete(scan)
    await db.commit()
    
    logger.warning(f"AUDIT | Admin {admin.email} deleted scan ID {scan_id} ({scan.target_domain})")
    
    return None


@router.get("/stats", response_model=schemas.AdminStatsResponse)
async def get_platform_stats(admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    """Efficient aggregate counts for the Admin dashboard."""
    users_res = await db.execute(select(func.count(User.id)))
    total_users = users_res.scalar() or 0
    
    prem_res = await db.execute(select(func.count(User.id)).where(User.subscription_tier == "Premium"))
    premium_users = prem_res.scalar() or 0
    
    scans_res = await db.execute(select(func.count(Scan.id)))
    total_scans = scans_res.scalar() or 0
    
    vuln_res = await db.execute(select(func.count(Vulnerability.id)))
    total_vulns = vuln_res.scalar() or 0
    
    return {
        "total_users": total_users,
        "premium_users": premium_users,
        "total_scans": total_scans,
        "total_vulnerabilities": total_vulns
    }
