from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func
from sqlalchemy.future import select

from backend.database import get_db
from backend.models import Scan, User, Vulnerability, Target
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

    # Target Inventory At-a-Glance
    result_recent = await db.execute(
        select(Target).order_by(Target.last_scan.desc().nullslast()).limit(10)
    )
    recent_targets = []
    for t in result_recent.scalars().all():
        recent_targets.append({
            "id": t.id,
            "domain": t.domain,
            "project_name": t.project_name,
            "last_scan": t.last_scan.isoformat() if t.last_scan else None,
            "total_endpoints": t.total_endpoints,
            "total_vulnerabilities": t.total_vulnerabilities,
            "risk_score": t.risk_score,
            "last_change_detected": t.last_change_detected.isoformat() if t.last_change_detected else None
        })

    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "vulnerabilities_found": total_vulns,
        "recent_targets": recent_targets
    }
