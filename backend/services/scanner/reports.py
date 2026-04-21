import os
import csv
from datetime import datetime

class ReportGenerator:
    @staticmethod
    def generate_reports(scan_id: int, target_domain: str, output_dir: str, db_objects: list):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        # Aggregate stats
        subdomains = [o for o in db_objects if getattr(o, "__tablename__", "") == "subdomains"]
        endpoints = [o for o in db_objects if getattr(o, "__tablename__", "") == "endpoints"]
        secrets = [o for o in db_objects if getattr(o, "__tablename__", "") == "secrets"]
        vulns = [o for o in db_objects if getattr(o, "__tablename__", "") == "vulnerabilities"]
        
        new_subs = sum(1 for o in subdomains if getattr(o, "is_new", False))
        new_eps = sum(1 for o in endpoints if getattr(o, "is_new", False))
        new_secs = sum(1 for o in secrets if getattr(o, "is_new", False))
        new_vulns = sum(1 for o in vulns if getattr(o, "is_new", False))
        
        crit_vulns = sum(1 for o in vulns if getattr(o, "severity", "") == "critical")
        high_vulns = sum(1 for o in vulns if getattr(o, "severity", "") == "high")
        
        # ── 1. executive_report.txt ───────────────────────────────────────────
        exec_path = os.path.join(output_dir, "executive_report.txt")
        exec_content = (
            f"{'='*60}\n"
            f"  EARTHEYE EXECUTIVE SUMMARY\n"
            f"{'='*60}\n"
            f"  Target:    {target_domain}\n"
            f"  Scan ID:   {scan_id}\n"
            f"  Generated: {ts}\n"
            f"{'='*60}\n\n"
            f"  [ATTACK SURFACE OVERVIEW]\n"
            f"  Subdomains : {len(subdomains)} (+{new_subs} new)\n"
            f"  Endpoints  : {len(endpoints)} (+{new_eps} new)\n"
            f"  Secrets    : {len(secrets)} (+{new_secs} new)\n"
            f"  Vulns      : {len(vulns)} (+{new_vulns} new)\n\n"
            f"  [RISK PRIORITIZATION]\n"
            f"  Critical Findings : {crit_vulns}\n"
            f"  High Findings     : {high_vulns}\n\n"
            f"  [MANUAL PENTEST CHECKLIST]\n"
            f"  [ ] Validate {crit_vulns} Critical vulnerabilities\n"
            f"  [ ] Rotate any active exposed secrets\n"
            f"  [ ] Review {new_eps} newly discovered endpoints for broken access control\n"
            f"  [ ] Check new subdomains for potential sub-domain takeover\n"
        )
        with open(exec_path, "w", encoding="utf-8") as f:
            f.write(exec_content)
            
        # ── 2. technical_recon.txt ────────────────────────────────────────────
        tech_path = os.path.join(output_dir, "technical_recon.txt")
        tech_content = (
            f"{'='*60}\n  EARTHEYE TECHNICAL RECONNAISSANCE\n{'='*60}\n"
            f"  Target: {target_domain} | Scan ID: {scan_id}\n\n"
            f"  [NEW ASSETS DETECTED]\n"
        )
        
        has_new = False
        for o in db_objects:
            if getattr(o, "is_new", False):
                has_new = True
                tname = getattr(o, "__tablename__", "")
                if tname == "subdomains":
                    tech_content += f"  [+] SUBDOMAIN: {getattr(o, 'domain', '')}\n"
                elif tname == "endpoints":
                    tech_content += f"  [+] ENDPOINT: {getattr(o, 'url', '')}\n"
                elif tname == "secrets":
                    tech_content += f"  [+] SECRET: {getattr(o, 'secret_type', '')} in {getattr(o, 'extracted_from', '')}\n"
                elif tname == "vulnerabilities":
                    tech_content += f"  [+] VULN ({getattr(o, 'severity', '')}): {getattr(o, 'description', '')}\n"
        
        if not has_new:
            tech_content += "  No new assets or findings in this scan cycle.\n"
            
        tech_content += "\n  [ALL VULNERABILITIES]\n"
        for o in vulns:
            tech_content += f"  - [{getattr(o, 'priority', '')} / {getattr(o, 'severity', '')}] {getattr(o, 'description', '')}\n"
            
        tech_content += "\n  [ALL SECRETS]\n"
        for o in secrets:
            tech_content += f"  - [{getattr(o, 'secret_type', '')}] {getattr(o, 'extracted_from', '')}\n"
            
        with open(tech_path, "w", encoding="utf-8") as f:
            f.write(tech_content)
            
        # ── 3. asset_inventory.csv ────────────────────────────────────────────
        csv_path = os.path.join(output_dir, "asset_inventory.csv")
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Asset Type", "Value", "Attributes", "Is New"])
            for o in subdomains:
                writer.writerow(["Subdomain", getattr(o, "domain", ""), "Alive", getattr(o, "is_new", False)])
            for o in endpoints:
                writer.writerow(["Endpoint", getattr(o, "url", ""), "", getattr(o, "is_new", False)])
            for o in secrets:
                writer.writerow(["Secret", getattr(o, "value", ""), getattr(o, "extracted_from", ""), getattr(o, "is_new", False)])
            for o in vulns:
                writer.writerow(["Vulnerability", getattr(o, "description", ""), getattr(o, "severity", ""), getattr(o, "is_new", False)])
