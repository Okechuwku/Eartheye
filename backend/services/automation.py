import asyncio
from datetime import datetime, timedelta

from sqlalchemy import func
from sqlalchemy.future import select

from backend.database import AsyncSessionLocal
from backend.models import MonitoringTarget, Scan, User
from backend.services.subscriptions import can_manage_automation


AUTOMATION_LOOP_INTERVAL_SECONDS = 60


class AutomationWorker:
    def __init__(self):
        self._task: asyncio.Task | None = None
        self._stopping = False

    def start(self):
        if self._task and not self._task.done():
            return
        self._stopping = False
        self._task = asyncio.create_task(self._run_loop())

    async def stop(self):
        self._stopping = True
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _run_loop(self):
        while not self._stopping:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # pragma: no cover - defensive background guard
                print(f"Automation worker tick failed: {exc}")
            await asyncio.sleep(AUTOMATION_LOOP_INTERVAL_SECONDS)

    async def tick(self):
        now = datetime.utcnow()
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(MonitoringTarget).where(
                    MonitoringTarget.enabled.is_(True),
                    (MonitoringTarget.next_run_at.is_(None)) | (MonitoringTarget.next_run_at <= now),
                )
            )
            targets = result.scalars().all()

            for target in targets:
                user_result = await db.execute(select(User).where(User.id == target.user_id))
                user = user_result.scalars().first()
                if not user or not can_manage_automation(user.role):
                    target.enabled = False
                    continue

                active_result = await db.execute(
                    select(func.count(Scan.id)).where(
                        Scan.monitoring_target_id == target.id,
                        Scan.status.in_(["Pending", "Running"]),
                    )
                )
                active_count = active_result.scalar() or 0
                if active_count:
                    continue

                scan = Scan(
                    user_id=user.id,
                    target_domain=target.domain,
                    scan_type=target.scan_type,
                    status="Pending",
                    created_at=now,
                    monitoring_target_id=target.id,
                )
                db.add(scan)
                target.next_run_at = now + timedelta(minutes=target.interval_minutes)
                await db.commit()
                await db.refresh(scan)

                from backend.services.scanner import trigger_scan_task

                trigger_scan_task(
                    scan.id,
                    target.domain,
                    target.scan_type,
                    user.role,
                    target.id,
                )


automation_worker = AutomationWorker()


async def record_monitoring_snapshot(monitoring_target_id: int | None, snapshot: dict):
    if not monitoring_target_id:
        return None

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(MonitoringTarget).where(MonitoringTarget.id == monitoring_target_id))
        target = result.scalars().first()
        if not target:
            return None

        previous = target.last_snapshot or {}
        diff = build_snapshot_diff(previous, snapshot)
        target.last_snapshot = snapshot
        target.last_diff = diff
        target.last_run_at = datetime.utcnow()
        target.next_run_at = datetime.utcnow() + timedelta(minutes=target.interval_minutes)
        await db.commit()
        return diff



def build_snapshot_diff(previous: dict, current: dict) -> dict:
    diff = {}
    tracked_keys = ["subdomains", "endpoints", "directories", "vulnerabilities", "secrets"]
    for key in tracked_keys:
        previous_values = set(previous.get(key, []))
        current_values = set(current.get(key, []))
        diff[f"new_{key}"] = sorted(current_values - previous_values)
    return diff
