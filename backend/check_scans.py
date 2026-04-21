import asyncio
from sqlalchemy.future import select
from backend.database import AsyncSessionLocal
from backend.models import Scan

async def main():
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).order_by(Scan.id.desc()).limit(5))
        scans = result.scalars().all()
        for s in scans:
            print(f"Scan {s.id}: {s.target_domain} - {s.status}")

asyncio.run(main())
