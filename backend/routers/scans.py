from datetime import datetime
import asyncio
import ipaddress
import os
import socket

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func
from typing import List
import re

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
from backend.services.scanner.coordinator import trigger_scan_task

router = APIRouter(prefix="/api/scans", tags=["scans"])

# Basic regex for a valid hostname / domain
DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
ALLOWED_SCAN_TYPES = {"Basic Scan", "Recon Scan", "Full Scan"}
ALLOW_PRIVATE_SCAN_TARGETS = os.getenv("ALLOW_PRIVATE_SCAN_TARGETS", "false").strip().lower() == "true"
MIN_AUTOMATION_INTERVAL_MINUTES = 60
MAX_AUTOMATION_INTERVAL_MINUTES = 10080
MAX_AUTOMATION_DOMAINS = int(os.getenv("MAX_AUTOMATION_DOMAINS", "50"))


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


def validate_scan_type(scan_type: str) -> str:
    normalized_type = (scan_type or "").strip()
    if normalized_type not in ALLOWED_SCAN_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan type. Allowed values: {', '.join(sorted(ALLOWED_SCAN_TYPES))}",
        )
    return normalized_type


async def verify_domain_is_public(target: str):
    if ALLOW_PRIVATE_SCAN_TARGETS:
        return

    try:
        addr_info = await asyncio.to_thread(socket.getaddrinfo, target, None)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="Domain verification failed: target does not resolve in public DNS")

    public_ips: set[str] = set()
    for entry in addr_info:
        ip_value = entry[4][0]
        try:
            parsed_ip = ipaddress.ip_address(ip_value)
        except ValueError:
            continue
        if parsed_ip.is_global:
            public_ips.add(ip_value)

    if not public_ips:
        raise HTTPException(
            status_code=400,
            detail="Domain verification failed: target resolves only to private or non-routable addresses",
        )


def ensure_scan_access(scan: Scan, current_user: User):
    if scan.user_id != current_user.id and not is_admin_role(current_user.role):
        raise HTTPException(status_code=403, detail="Not enough permissions")

@router.post("/", response_model=schemas.ScanResponse)
async def create_scan(scan_in: schemas.ScanCreate, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    target = validate_domain(scan_in.target_domain)
    scan_type = validate_scan_type(scan_in.scan_type)
    await verify_domain_is_public(target)
    role = normalize_role(current_user.role)

    if not can_run_scan(role, scan_type):
        raise HTTPException(
            status_code=403,
            detail="Free users can only run Basic Scan. Upgrade to Premium to unlock recon, JavaScript intelligence, GraphQL, ffuf, and nuclei.",
        )

    # 1.5 Tier Check
    if scan_in.scan_type in ["Recon Scan", "Full Scan"] and current_user.subscription_tier != "Premium" and current_user.role != "Admin":
        raise HTTPException(status_code=403, detail="Premium subscription required for advanced recon.")

    # 2. Rate Limiting / Scan Limits
    result = await db.execute(
        select(func.count(Scan.id)).where(Scan.user_id == current_user.id, Scan.status.in_(["Pending", "Running"]))
    )
    active_count = result.scalar() or 0
    if active_count >= 100:
        raise HTTPException(status_code=429, detail="Maximum concurrent scan limit reached. Please wait for active operations to complete.")


    new_scan = Scan(
        user_id=current_user.id,
        target_domain=target,
        scan_type=scan_type,
        status="Pending",
        created_at=datetime.utcnow(),
        summary={},
        graph_data={},
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    trigger_scan_task(new_scan.id, target, scan_type, role)
    return new_scan

@router.get("/", response_model=List[schemas.ScanResponse])
async def list_scans(current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()))
    return result.scalars().all()

@router.get("/{scan_id}", response_model=schemas.DetailedScanResponse)
async def get_scan(scan_id: int, current_user: User = Depends(auth.get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalars().first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.user_id != current_user.id and current_user.role != "Admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
        
    # Fetch relations
    from backend.models import Subdomain, Endpoint, Vulnerability, Technology, GraphQL, JavaScript, Secret
    
    subs = await db.execute(select(Subdomain).where(Subdomain.scan_id == scan_id))
    scan.subdomains = subs.scalars().all()
    
    eps = await db.execute(select(Endpoint).where(Endpoint.scan_id == scan_id))
    scan.endpoints = eps.scalars().all()
    
    vulns = await db.execute(select(Vulnerability).where(Vulnerability.scan_id == scan_id))
    scan.vulnerabilities = vulns.scalars().all()
    
    techs = await db.execute(select(Technology).where(Technology.scan_id == scan_id))
    scan.technologies = techs.scalars().all()

    gql = await db.execute(select(GraphQL).where(GraphQL.scan_id == scan_id))
    scan.graphql_endpoints = gql.scalars().all()

    js = await db.execute(select(JavaScript).where(JavaScript.scan_id == scan_id))
    scan.javascript_files = js.scalars().all()

    secs = await db.execute(select(Secret).where(Secret.scan_id == scan_id))
    scan.secrets = secs.scalars().all()
    
    return scan

