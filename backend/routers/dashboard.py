from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func
from sqlalchemy.future import select

from backend.database import get_db
from backend.models import Scan, User, Vulnerability
from backend import auth

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

@router.get("/stats")
async def get_dashboard_stats(current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    # Total scans
    result_scans = await db.execute(select(func.count(Scan.id)).where(Scan.user_id == current_user.id))
    total_scans = result_scans.scalar() or 0
    
    # Active scans
    result_active = await db.execute(select(func.count(Scan.id)).where(Scan.user_id == current_user.id, Scan.status == "Running"))
    active_scans = result_active.scalar() or 0
    
    # Vulnerabilities found
    result_vulns = await db.execute(
        select(func.count(Vulnerability.id))
        .join(Scan, Scan.id == Vulnerability.scan_id)
        .where(Scan.user_id == current_user.id)
    )
    total_vulns = result_vulns.scalar() or 0

    # Recent targets
    result_recent = await db.execute(
        select(Scan.target_domain).where(Scan.user_id == current_user.id)
        .order_by(Scan.created_at.desc()).limit(5)
    )
    recent_targets = [row for row in result_recent.scalars().all()]

    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "vulnerabilities_found": total_vulns,
        "recent_targets": recent_targets
    }
