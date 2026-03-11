import os
import shutil

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func, delete
from typing import List

from backend.database import get_db
from backend.models import GraphQLFinding, MonitoringTarget, Scan, SecretFinding, User, Vulnerability, Directory, Endpoint, Subdomain
from backend import schemas, auth
from backend.services.subscriptions import normalize_role, subscription_plan_for_role

router = APIRouter(prefix="/api/admin", tags=["admin"])


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
    result = await db.execute(select(User))
    users = result.scalars().all()
    for user in users:
        user.role = normalize_role(user.role)
        user.subscription_plan = subscription_plan_for_role(user.role)
        user.subscription_status = user.subscription_status or "active"
    return users

@router.get("/scans", response_model=List[schemas.ScanResponse])
async def list_all_scans(admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).order_by(Scan.created_at.desc()))
    return result.scalars().all()


@router.get("/vulnerabilities")
async def list_all_vulnerabilities(admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Vulnerability, Scan).join(Scan, Scan.id == Vulnerability.scan_id).order_by(Vulnerability.id.desc()))
    return [
        {
            "id": vulnerability.id,
            "scan_id": scan.id,
            "target_domain": scan.target_domain,
            "severity": vulnerability.severity,
            "description": vulnerability.description,
            "tool": vulnerability.tool,
            "matched_at": vulnerability.matched_at,
        }
        for vulnerability, scan in result.all()
    ]


@router.get("/secrets")
async def list_all_secrets(admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(SecretFinding, Scan).join(Scan, Scan.id == SecretFinding.scan_id).order_by(SecretFinding.id.desc()))
    return [
        {
            "id": secret.id,
            "scan_id": scan.id,
            "target_domain": scan.target_domain,
            "category": secret.category,
            "severity": secret.severity,
            "location": secret.location,
            "value_preview": secret.value_preview,
        }
        for secret, scan in result.all()
    ]


@router.get("/graphql")
async def list_all_graphql_findings(admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(GraphQLFinding, Scan).join(Scan, Scan.id == GraphQLFinding.scan_id).order_by(GraphQLFinding.id.desc()))
    return [
        {
            "id": finding.id,
            "scan_id": scan.id,
            "target_domain": scan.target_domain,
            "endpoint": finding.endpoint,
            "introspection_enabled": finding.introspection_enabled,
            "schema_types": finding.schema_types,
            "notes": finding.notes,
        }
        for finding, scan in result.all()
    ]


@router.patch("/users/{user_id}/subscription", response_model=schemas.UserResponse)
async def update_user_subscription(user_id: int, payload: schemas.SubscriptionUpdate, admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalars().first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = normalize_role(payload.role)
    user.subscription_plan = subscription_plan_for_role(user.role)
    user.subscription_status = payload.subscription_status
    await db.commit()
    await db.refresh(user)
    return user


@router.get("/scans/{scan_id}/report")
async def download_scan_report(scan_id: int, admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.report_path or not os.path.exists(scan.report_path):
        raise HTTPException(status_code=404, detail="Recon report not available")
    return FileResponse(scan.report_path, filename=os.path.basename(scan.report_path), media_type="text/plain")


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int, admin: User = Depends(auth.get_current_admin), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target_domain = scan.target_domain
    output_dir = scan.output_dir

    for model in [GraphQLFinding, SecretFinding, Vulnerability, Directory, Endpoint, Subdomain]:
        await db.execute(delete(model).where(model.scan_id == scan_id))

    await db.delete(scan)
    await db.commit()

    remaining = (
        await db.execute(select(func.count(Scan.id)).where(Scan.target_domain == target_domain))
    ).scalar() or 0
    if remaining == 0 and output_dir and os.path.exists(output_dir):
        shutil.rmtree(output_dir, ignore_errors=True)

    return {"detail": "Scan deleted"}
