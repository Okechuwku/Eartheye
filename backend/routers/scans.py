from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func
from typing import List
import re
import os

from backend.database import get_db
from backend.models import (
    Directory,
    Endpoint,
    GraphQLFinding,
    MonitoringTarget,
    Scan,
    SecretFinding,
    Subdomain,
    User,
    Vulnerability,
)
from backend import schemas, auth
from backend.services.scanner import trigger_scan_task
from backend.services.subscriptions import can_manage_automation, can_run_scan, is_admin_role, normalize_role

router = APIRouter(prefix="/api/scans", tags=["scans"])

# Basic regex for a valid hostname / domain
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


def normalize_domain(raw_value: str) -> str:
    target = raw_value.strip().lower()
    if target.startswith("http://") or target.startswith("https://"):
        target = target.split("://", 1)[1].split("/", 1)[0]
    return target


def validate_domain(raw_value: str) -> str:
    target = normalize_domain(raw_value)
    if not DOMAIN_REGEX.match(target):
        raise HTTPException(status_code=400, detail="Invalid domain format. Please provide a valid hostname (e.g., example.com)")
    return target


def ensure_scan_access(scan: Scan, current_user: User):
    if scan.user_id != current_user.id and not is_admin_role(current_user.role):
        raise HTTPException(status_code=403, detail="Not enough permissions")

@router.post("/", response_model=schemas.ScanResponse)
async def create_scan(scan_in: schemas.ScanCreate, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    target = validate_domain(scan_in.target_domain)
    role = normalize_role(current_user.role)

    if not can_run_scan(role, scan_in.scan_type):
        raise HTTPException(
            status_code=403,
            detail="Free users can only run Basic Scan. Upgrade to Premium to unlock recon, JavaScript intelligence, GraphQL, ffuf, and nuclei.",
        )

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
        created_at=datetime.utcnow(),
        summary={},
        graph_data={},
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    trigger_scan_task(new_scan.id, target, scan_in.scan_type, role)
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
    ensure_scan_access(scan, current_user)
    return scan


@router.get("/{scan_id}/results", response_model=schemas.ScanResultsResponse)
async def get_scan_results(scan_id: int, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    ensure_scan_access(scan, current_user)

    subdomains_result = await db.execute(select(Subdomain).where(Subdomain.scan_id == scan_id).order_by(Subdomain.domain.asc()))
    endpoints_result = await db.execute(select(Endpoint).where(Endpoint.scan_id == scan_id).order_by(Endpoint.url.asc()))
    directories_result = await db.execute(select(Directory).where(Directory.scan_id == scan_id).order_by(Directory.path.asc()))
    vulnerabilities_result = await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id).order_by(Vulnerability.severity.asc(), Vulnerability.description.asc()))
    secrets_result = await db.execute(select(SecretFinding).where(SecretFinding.scan_id == scan_id).order_by(SecretFinding.severity.asc(), SecretFinding.category.asc()))
    graphql_result = await db.execute(select(GraphQLFinding).where(GraphQLFinding.scan_id == scan_id).order_by(GraphQLFinding.endpoint.asc()))

    report_download_url = f"/api/scans/{scan_id}/report" if scan.report_path else None
    return {
        "scan": scan,
        "subdomains": subdomains_result.scalars().all(),
        "endpoints": endpoints_result.scalars().all(),
        "directories": directories_result.scalars().all(),
        "vulnerabilities": vulnerabilities_result.scalars().all(),
        "secrets": secrets_result.scalars().all(),
        "graphql_findings": graphql_result.scalars().all(),
        "graph_data": scan.graph_data or {},
        "summary": scan.summary or {},
        "report_download_url": report_download_url,
    }


@router.get("/{scan_id}/report")
async def download_scan_report(scan_id: int, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    ensure_scan_access(scan, current_user)
    if not scan.report_path or not os.path.exists(scan.report_path):
        raise HTTPException(status_code=404, detail="Recon report not available")
    return FileResponse(scan.report_path, filename=os.path.basename(scan.report_path), media_type="text/plain")


@router.post("/automation/targets", response_model=List[schemas.MonitoringTargetResponse])
async def create_automation_targets(payload: schemas.AutomationBatchCreate, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    if not can_manage_automation(current_user.role):
        raise HTTPException(status_code=403, detail="Continuous monitoring is available to Premium and Administrator accounts only")

    if not payload.domains:
        raise HTTPException(status_code=400, detail="At least one domain is required")

    domains = sorted({validate_domain(domain) for domain in payload.domains})
    targets: list[MonitoringTarget] = []

    for domain in domains:
        result = await db.execute(
            select(MonitoringTarget).where(MonitoringTarget.user_id == current_user.id, MonitoringTarget.domain == domain)
        )
        target = result.scalars().first()
        if not target:
            target = MonitoringTarget(
                user_id=current_user.id,
                domain=domain,
                scan_type=payload.scan_type,
                interval_minutes=payload.interval_minutes,
                enabled=True,
                next_run_at=datetime.utcnow(),
                last_snapshot={},
                last_diff={},
            )
            db.add(target)
        else:
            target.scan_type = payload.scan_type
            target.interval_minutes = payload.interval_minutes
            target.enabled = True
            target.next_run_at = datetime.utcnow()
        targets.append(target)

    await db.commit()
    for target in targets:
        await db.refresh(target)
    return targets


@router.get("/automation/targets", response_model=List[schemas.MonitoringTargetResponse])
async def list_automation_targets(current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(MonitoringTarget).where(MonitoringTarget.user_id == current_user.id).order_by(MonitoringTarget.created_at.desc())
    )
    return result.scalars().all()


@router.patch("/automation/targets/{target_id}", response_model=schemas.MonitoringTargetResponse)
async def update_automation_target(target_id: int, payload: schemas.AutomationTargetUpdate, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(MonitoringTarget).where(MonitoringTarget.id == target_id))
    target = result.scalars().first()
    if not target or target.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Monitoring target not found")

    target.enabled = payload.enabled
    if payload.enabled and not target.next_run_at:
        target.next_run_at = datetime.utcnow()
    await db.commit()
    await db.refresh(target)
    return target


@router.delete("/automation/targets/{target_id}")
async def delete_automation_target(target_id: int, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(MonitoringTarget).where(MonitoringTarget.id == target_id))
    target = result.scalars().first()
    if not target or target.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Monitoring target not found")

    await db.delete(target)
    await db.commit()
    return {"detail": "Monitoring target deleted"}
