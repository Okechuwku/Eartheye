import os
import json
import asyncio
from datetime import datetime, timezone
from backend.routers.websockets import manager
from backend.database import AsyncSessionLocal
from backend.models import Scan, Subdomain, Endpoint, Vulnerability, GraphQL, JavaScript, Secret, Target
from sqlalchemy.future import select
from sqlalchemy import desc
from .executor import SubprocessExecutor
from .discovery import DiscoveryModule
from .crawler import CrawlingModule
from .javascript import JavaScriptIntelModule
from .graphql import GraphQLModule
from .safe_vuln import SafeVulnerabilityModule
from .secrets import SecretDetectionModule
from .screenshots import ScreenshotModule
from .triage import TriageModule
from .reports import ReportGenerator

SCANS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../../scans"))


async def _write_scan_log(output_dir: str, entries: list[dict]):
    """Persist structured log entries to scan_log.txt for offline review."""
    log_path = os.path.join(output_dir, "scan_log.txt")
    with open(log_path, "a", encoding="utf-8") as fh:
        for e in entries:
            ts = e.get("timestamp", "")
            mod = e.get("module", "System")
            lvl = e.get("level", "info").upper()
            msg = e.get("message", "")
            fh.write(f"[{ts}] [{mod}] [{lvl}] {msg}\n")


async def parse_and_save_results(scan_id: int, target_domain: str, output_dir: str):
    """
    Read all artifact files produced by scanner modules, triage them,
    write triage.json, then persist everything to the database.
    Performs historical diff tracking against previous scans.
    """
    db_objects = []
    raw_vulns = []

    historical_subs = set()
    historical_eps = set()
    historical_secrets = set()
    historical_vulns = set()

    async with AsyncSessionLocal() as db:
        prev_result = await db.execute(
            select(Scan)
            .where(Scan.target_domain == target_domain, Scan.status == "Completed", Scan.id < scan_id)
            .order_by(desc(Scan.id))
            .limit(1)
        )
        prev_scan = prev_result.scalars().first()
        if prev_scan:
            s_res = await db.execute(select(Subdomain.domain).where(Subdomain.scan_id == prev_scan.id))
            historical_subs = set(s_res.scalars().all())
            
            e_res = await db.execute(select(Endpoint.url).where(Endpoint.scan_id == prev_scan.id))
            historical_eps = set(e_res.scalars().all())
            
            sec_res = await db.execute(select(Secret.value).where(Secret.scan_id == prev_scan.id))
            historical_secrets = set(sec_res.scalars().all())
            
            v_res = await db.execute(select(Vulnerability.description).where(Vulnerability.scan_id == prev_scan.id))
            historical_vulns = set(v_res.scalars().all())

    # ── Subdomains ────────────────────────────────────────────────────────────
    sub_file = os.path.join(output_dir, "subdomains.txt")
    if os.path.exists(sub_file):
        with open(sub_file) as f:
            for line in f:
                val = line.strip()
                if val:
                    db_objects.append(Subdomain(scan_id=scan_id, domain=val, is_alive=True, is_new=(val not in historical_subs)))

    # ── Endpoints ─────────────────────────────────────────────────────────────
    ep_file = os.path.join(output_dir, "endpoints.txt")
    if os.path.exists(ep_file):
        with open(ep_file) as f:
            for line in f:
                val = line.strip()
                if val:
                    db_objects.append(Endpoint(scan_id=scan_id, url=val, is_new=(val not in historical_eps)))

    # ── Vulnerabilities (Safe Heuristics) ─────────────────────────────────────
    vuln_file = os.path.join(output_dir, "vulnerabilities.json")
    if os.path.exists(vuln_file):
        with open(vuln_file) as f:
            for line in f:
                if line.strip():
                    try:
                        v = json.loads(line)
                        info = v.get("info", {})
                        raw_vulns.append({
                            "severity":    info.get("severity", "unknown"),
                            "description": info.get("name", "unknown"),
                            "tool":        "nuclei",
                        })
                    except Exception:
                        pass

    # ── Triage all vulnerabilities in batch ───────────────────────────────────
    triaged = TriageModule.triage_finding_list(raw_vulns)
    triage_out = os.path.join(output_dir, "triage.json")
    with open(triage_out, "w") as f:
        json.dump(triaged, f, indent=2)

    for t in triaged:
        desc_val = t.get("description", "unknown")
        db_objects.append(Vulnerability(
            scan_id=scan_id,
            severity=t.get("severity", "unknown"),
            description=desc_val,
            tool=t.get("tool", "nuclei"),
            confidence=t.get("confidence", "Medium"),
            exposure_level=t.get("exposure_level", "High"),
            priority=t.get("priority", "Low"),
            manual_review_required=t.get("manual_review_required", False),
            is_new=(desc_val not in historical_vulns)
        ))

    # ── JavaScript Intel ──────────────────────────────────────────────────────
    js_file = os.path.join(output_dir, "javascript_intel.json")
    if os.path.exists(js_file):
        try:
            with open(js_file) as f:
                js_data = json.load(f)
            for item in js_data:
                db_objects.append(JavaScript(
                    scan_id=scan_id,
                    url=item.get("url"),
                    extracted_endpoints=json.dumps(item.get("extracted_endpoints", [])),
                    extracted_parameters=json.dumps(item.get("extracted_parameters", [])),
                ))
        except Exception:
            pass

    # ── GraphQL ───────────────────────────────────────────────────────────────
    gql_file = os.path.join(output_dir, "graphql.json")
    if os.path.exists(gql_file):
        try:
            with open(gql_file) as f:
                gql_data = json.load(f)
            for item in gql_data:
                db_objects.append(GraphQL(
                    scan_id=scan_id,
                    endpoint=item.get("endpoint"),
                    has_introspection=item.get("has_introspection", False),
                ))
        except Exception:
            pass

    # ── Secrets ───────────────────────────────────────────────────────────────
    secrets_file = os.path.join(output_dir, "secrets.json")
    if os.path.exists(secrets_file):
        try:
            with open(secrets_file) as f:
                sec_data = json.load(f)
            for item in sec_data:
                val = item.get("value_redacted", item.get("value", ""))
                db_objects.append(Secret(
                    scan_id=scan_id,
                    value=val,
                    extracted_from=item.get("extracted_from", ""),
                    secret_type=item.get("secret_type", "Unknown"),
                    is_new=(val not in historical_secrets)
                ))
        except Exception:
            pass

    # ── Persist to DB + mark scan complete ───────────────────────────────────
    # ── Persist to DB + mark scan complete + update target stats ─────────────
    async with AsyncSessionLocal() as db:
        if db_objects:
            db.add_all(db_objects)
        
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalars().first()
        if scan:
            scan.status = "Completed"

        target_res = await db.execute(select(Target).where(Target.domain == target_domain))
        target = target_res.scalars().first()
        if target:
            target.last_scan = datetime.utcnow()
            target.total_subdomains = sum(1 for o in db_objects if isinstance(o, Subdomain))
            target.total_endpoints = sum(1 for o in db_objects if isinstance(o, Endpoint))
            target.total_vulnerabilities = sum(1 for o in db_objects if isinstance(o, Vulnerability))
            
            score = 0
            for o in db_objects:
                if isinstance(o, Vulnerability):
                    s = getattr(o, "severity", "")
                    if s == "critical": score += 25
                    elif s == "high": score += 10
                    elif s == "medium": score += 5
                    elif s == "low": score += 1
            target.risk_score = min(100, score)
            
            has_new = any(getattr(o, "is_new", False) for o in db_objects)
            if has_new:
                target.last_change_detected = datetime.utcnow()

        await db.commit()
        return db_objects


async def _safe_run_scan(scan_id: int, target_domain: str, scan_type: str):
    """Core asynchronous background worker. Each module is isolated — failures don't crash the pipeline."""
    output_dir = os.path.join(SCANS_DIR, target_domain, str(scan_id))
    log_buffer: list[dict] = []

    async def log(message: str, module: str = "System", level: str = "info"):
        entry = {
            "type": "log",
            "scan_id": scan_id,
            "module": module,
            "level": level,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        log_buffer.append(entry)
        await manager.broadcast_log(scan_id, message, module, level)

    try:
        os.makedirs(output_dir, exist_ok=True)
        executor = SubprocessExecutor(use_mock_fallback=True)

        await log(f"Initializing {scan_type} on target: {target_domain}", "System", "info")
        await asyncio.sleep(0.3)

        # ── Discovery (all scan types) ────────────────────────────────────────
        ep_out = os.path.join(output_dir, "endpoints.txt")
        try:
            _, ep_out_ret = await DiscoveryModule(executor).run(scan_id, target_domain, output_dir)
            ep_out = ep_out_ret
        except Exception as e:
            await log(f"Discovery module error (falling back to root domain): {e}", "Discovery", "error")
            with open(ep_out, "w") as f:
                f.write(f"https://{target_domain}\n")

        if scan_type in ("Full Scan", "Recon Scan"):
            # ── Crawling ──────────────────────────────────────────────────────
            try:
                ep_out = await CrawlingModule(executor).run(scan_id, ep_out, output_dir)
            except Exception as e:
                await log(f"Crawler module error (non-fatal): {e}", "Crawler", "warn")

            # ── Visual Triage ─────────────────────────────────────────────────
            try:
                await ScreenshotModule().run(scan_id, ep_out, output_dir)
            except Exception as e:
                await log(f"Screenshots module error (non-fatal): {e}", "Screenshots", "warn")

            # ── JavaScript Intel ──────────────────────────────────────────────
            try:
                await JavaScriptIntelModule().run(scan_id, ep_out, output_dir)
            except Exception as e:
                await log(f"JavaScript module error (non-fatal): {e}", "JavaScript", "warn")

            # ── GraphQL ───────────────────────────────────────────────────────
            try:
                await GraphQLModule().run(scan_id, ep_out, output_dir)
            except Exception as e:
                await log(f"GraphQL module error (non-fatal): {e}", "GraphQL", "warn")

            # ── Secret Detection ──────────────────────────────────────────────
            try:
                await SecretDetectionModule().run(scan_id, ep_out, output_dir)
            except Exception as e:
                await log(f"Secrets module error (non-fatal): {e}", "Secrets", "warn")

            # ── Safe Vulnerability Scan ───────────────────────────────────────
            try:
                await SafeVulnerabilityModule(executor).run(scan_id, ep_out, output_dir)
            except Exception as e:
                await log(f"SafeVuln module error (non-fatal): {e}", "SafeVuln", "warn")

        # ── Triage + DB Persist ───────────────────────────────────────────────
        await log("Analyzing and triaging all findings...", "System", "info")
        db_objects = await parse_and_save_results(scan_id, target_domain, output_dir)

        # ── Report Generation ─────────────────────────────────────────────────
        if scan_type in ("Full Scan", "Recon Scan"):
            await log("Compiling executive and technical reports...", "System", "info")
            try:
                ReportGenerator.generate_reports(scan_id, target_domain, output_dir, db_objects)
            except Exception as e:
                await log(f"Report generation error (non-fatal): {e}", "System", "warn")

        # ── Write scan_log.txt ────────────────────────────────────────────────
        await _write_scan_log(output_dir, log_buffer)

        await manager.broadcast_log(scan_id, "Scan completed. All artifacts structured and findings triaged.", "System", "success")
        await manager.broadcast_event(scan_id, "scan_complete", "System", {"output_dir": output_dir})

    except Exception as e:
        await manager.broadcast_log(scan_id, f"CRITICAL EXCEPTION — {type(e).__name__}: {e}", "System", "critical")
        await manager.broadcast_event(scan_id, "scan_failed", "System", {"error": str(e)})
        async with AsyncSessionLocal() as db:
            from sqlalchemy.future import select
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalars().first()
            if scan:
                scan.status = "Failed"
                await db.commit()


def trigger_scan_task(scan_id: int, target_domain: str, scan_type: str):
    """Public entry point — fires the decoupled background worker."""
    asyncio.create_task(_safe_run_scan(scan_id, target_domain, scan_type))
