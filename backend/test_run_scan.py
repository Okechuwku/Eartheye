import asyncio
from backend.services.scanner.coordinator import _safe_run_scan
from backend.database import AsyncSessionLocal
from backend.models import Scan
import os

async def main():
    async with AsyncSessionLocal() as db:
        new_scan = Scan(user_id=1, target_domain="example.com", scan_type="Full Scan", status="Pending")
        db.add(new_scan)
        await db.commit()
        await db.refresh(new_scan)
        scan_id = new_scan.id
        
    print(f"Triggering scan for example.com with id {scan_id}")
    await _safe_run_scan(scan_id, "example.com", "Full Scan")
    print("Scan complete.")

asyncio.run(main())
