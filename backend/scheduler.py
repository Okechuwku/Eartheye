import asyncio
from datetime import datetime, timedelta
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.future import select

from backend.database import AsyncSessionLocal
from backend.models import ScheduledJob, Target, Scan, User
from backend.services.scanner.coordinator import trigger_scan_task

logger = logging.getLogger(__name__)

async def run_scheduled_scans():
    """ 
    Master polling job to execute scheduled scans.
    It checks PostgreSQL for jobs needing execution and dispatches them via asyncio.
    """
    try:
        async with AsyncSessionLocal() as db:
            now = datetime.utcnow()
            # Fetch active jobs where next_run is null or in the past
            result = await db.execute(
                select(ScheduledJob).where(
                    ScheduledJob.is_active == True,
                    (ScheduledJob.next_run == None) | (ScheduledJob.next_run <= now)
                )
            )
            jobs = result.scalars().all()
            
            for job in jobs:
                # 1. Fetch Target
                target_res = await db.execute(select(Target).where(Target.id == job.target_id))
                target = target_res.scalars().first()
                if not target:
                    continue
                    
                # 2. Get Admin User for scan attribution
                admin_res = await db.execute(select(User).where(User.role == "Admin"))
                admin = admin_res.scalars().first()
                if not admin:
                    continue
                
                logger.info(f"Triggering scheduled continuous monitoring scan for {target.domain}")
                
                # 3. Create Scan Record
                scan = Scan(
                    user_id=admin.id,
                    target_domain=target.domain,
                    status="Pending",
                    scan_type="Recon Scan" # Continuous monitoring default
                )
                db.add(scan)
                await db.commit()
                await db.refresh(scan)
                
                # 4. Fire and forget the coordinator
                trigger_scan_task(scan.id, target.domain, "Recon Scan")
                
                
                # 5. Update next_run based on interval
                if job.schedule_interval == "daily":
                    job.next_run = now + timedelta(days=1)
                elif job.schedule_interval == "weekly":
                    job.next_run = now + timedelta(weeks=1)
                elif job.schedule_interval == "monthly":
                    job.next_run = now + timedelta(days=30)
                else:
                    job.next_run = now + timedelta(hours=1)
                
                await db.commit()
    except Exception as e:
        logger.error(f"Scheduler tracking error: {str(e)}")

def start_scheduler():
    scheduler = AsyncIOScheduler()
    # Run the master polling job every 5 minutes
    scheduler.add_job(run_scheduled_scans, 'interval', minutes=5)
    scheduler.start()
    logger.info("Eartheye continuous monitoring scheduler started.")
