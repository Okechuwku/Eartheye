import asyncio
import os
import json
from datetime import datetime

from backend.routers.websockets import manager
from backend.database import AsyncSessionLocal
from backend.models import Scan, Subdomain, Endpoint, Vulnerability

SCANS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../scans"))

async def run_cmd_with_logs(scan_id: int, cmd: list, cwd: str):
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=cwd
    )
    
    while True:
        line = await process.stdout.readline()
        if not line:
            break
        decoded_line = line.decode('utf-8', errors='replace').strip()
        if decoded_line:
            await manager.broadcast_log(scan_id, f"[{datetime.utcnow().strftime('%H:%M:%S')}] {decoded_line}")
            
    await process.wait()
    return process.returncode

async def parse_and_save_results(scan_id: int, target_domain: str, output_dir: str):
    subdomains_file = os.path.join(output_dir, "subdomains.txt")
    subs_found = []
    if os.path.exists(subdomains_file):
        with open(subdomains_file, "r") as f:
            for line in f:
                domain = line.strip()
                if domain:
                    subs_found.append(Subdomain(scan_id=scan_id, domain=domain, is_alive=True))
                    
    endpoints_file = os.path.join(output_dir, "endpoints.txt")
    endpoints_found = []
    if os.path.exists(endpoints_file):
        with open(endpoints_file, "r") as f:
            for line in f:
                url = line.strip()
                if url:
                    endpoints_found.append(Endpoint(scan_id=scan_id, url=url))

    vulns_file = os.path.join(output_dir, "vulnerabilities.json")
    vulns_found = []
    if os.path.exists(vulns_file):
        with open(vulns_file, "r") as f:
            for line in f:
                if line.strip():
                    try:
                        data = json.loads(line)
                        info = data.get("info", {})
                        vulns_found.append(Vulnerability(
                            scan_id=scan_id,
                            severity=info.get("severity", "unknown"),
                            description=info.get("name", "unknown"),
                            tool="nuclei"
                        ))
                    except json.JSONDecodeError:
                        pass
                        
    async with AsyncSessionLocal() as db:
        if subs_found:
            db.add_all(subs_found)
        if endpoints_found:
            db.add_all(endpoints_found)
        if vulns_found:
            db.add_all(vulns_found)
        
        from sqlalchemy.future import select
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalars().first()
        if scan:
            scan.status = "Completed"
        
        await db.commit()

async def run_scan(scan_id: int, target_domain: str, scan_type: str):
    output_dir = os.path.join(SCANS_DIR, target_domain, str(scan_id))
    os.makedirs(output_dir, exist_ok=True)
    
    await manager.broadcast_log(scan_id, f"[*] Starting {scan_type} on {target_domain}")
    
    subdomains_out = os.path.join(output_dir, "subdomains.txt")
    await manager.broadcast_log(scan_id, f"[+] Running subfinder...")
    await run_cmd_with_logs(scan_id, ["subfinder", "-d", target_domain, "-o", subdomains_out], output_dir)
    
    endpoints_out = os.path.join(output_dir, "endpoints.txt")
    await manager.broadcast_log(scan_id, f"[+] Running httpx...")
    if os.path.exists(subdomains_out):
        await run_cmd_with_logs(scan_id, ["httpx", "-l", subdomains_out, "-o", endpoints_out], output_dir)
    else:
        await run_cmd_with_logs(scan_id, ["httpx", "-u", target_domain, "-o", endpoints_out], output_dir)
        
    if scan_type in ["Full Scan", "Recon Scan"]:
        katana_out = os.path.join(output_dir, "katana_endpoints.txt")
        await manager.broadcast_log(scan_id, f"[+] Running katana...")
        if os.path.exists(endpoints_out):
            await run_cmd_with_logs(scan_id, ["katana", "-list", endpoints_out, "-o", katana_out], output_dir)

        if os.path.exists(katana_out):
            with open(endpoints_out, "a") as f:
                with open(katana_out, "r") as fk:
                    f.write(fk.read())
                    
        await manager.broadcast_log(scan_id, f"[+] Running LinkFinder... (Skipping executable due to lack of standard package)")
        await manager.broadcast_log(scan_id, f"[+] Running ffuf... (Skipping executable due to lack of dictionary)")
        
        vulns_out = os.path.join(output_dir, "vulnerabilities.json")
        await manager.broadcast_log(scan_id, f"[+] Running nuclei...")
        target_list = endpoints_out if os.path.exists(endpoints_out) else subdomains_out
        if os.path.exists(target_list):
            await run_cmd_with_logs(scan_id, ["nuclei", "-l", target_list, "-json-export", vulns_out], output_dir)
            
    await manager.broadcast_log(scan_id, f"[*] Scan completed. Parsing results...")
    
    await parse_and_save_results(scan_id, target_domain, output_dir)
    await manager.broadcast_log(scan_id, f"[*] Results saved to database.")

def trigger_scan_task(scan_id: int, target_domain: str, scan_type: str):
    asyncio.create_task(run_scan(scan_id, target_domain, scan_type))
