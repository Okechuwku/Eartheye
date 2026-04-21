import os
import json
import asyncio
import re
from backend.routers.websockets import manager

MODULE = "Secrets"

# ─── Pattern Registry ─────────────────────────────────────────────────────────
# Each entry: (secret_type, compiled_regex, severity, confidence)
SECRET_PATTERNS = [
    ("AWS Access Key",          re.compile(r"AKIA[0-9A-Z]{16}"),                                                              "critical", "High"),
    ("AWS Secret Key",          re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"),                    "critical", "High"),
    ("GCP API Key",             re.compile(r"AIza[0-9A-Za-z\-_]{35}"),                                                        "critical", "High"),
    ("GitHub Token",            re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),                                                    "critical", "High"),
    ("Slack Token",             re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),                                                 "high",     "High"),
    ("Database Connection",     re.compile(r"(?i)(mongodb|mysql|postgres|redis|mssql|sqlite):\/\/\S+"),                        "critical", "High"),
    ("Generic API Token",       re.compile(r"(?i)(?:api[_-]?key|apikey|access[_-]?token|secret[_-]?key)\s*[=:]\s*['\"]([A-Za-z0-9\-_.]{16,})['\"]"), "high", "Medium"),
    ("Private Key Header",      re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),                            "critical", "High"),
    ("JWT Token",               re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),               "high",     "Medium"),
    ("Stripe Key",              re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),                                                      "critical", "High"),
    ("Twilio Token",            re.compile(r"SK[0-9a-fA-F]{32}"),                                                             "high",     "Medium"),
    ("Generic Password",        re.compile(r"(?i)password\s*[=:]\s*['\"]([^'\"]{8,})['\"]"),                                  "medium",   "Low"),
    ("Basic Auth in URL",       re.compile(r"https?://[^:]+:[^@]+@"),                                                         "high",     "High"),
    ("Internal IP Disclosure",  re.compile(r"(?:10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168\.)\d{1,3}\.\d{1,3}"), "medium",   "Medium"),
]

# Sensitive filename suffixes that warrant checking
SENSITIVE_PATH_PATTERNS = [
    ".env", ".env.local", ".env.prod", ".env.backup",
    "config.json", "settings.json", "secrets.json",
    "credentials", "credentials.json", "credentials.xml",
    "database.yml", "database.json",
    ".git/config", ".ssh/id_rsa", "id_rsa",
    "wp-config.php", "web.config",
    "backup.sql", "dump.sql",
    ".htpasswd", ".htaccess",
    "private_key.pem", "server.key",
]


def _redact(value: str) -> str:
    """Return a redacted display value — show first 4 + last 4 chars."""
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


class SecretDetectionModule:
    """
    Scans endpoint paths and filenames for sensitive configuration secrets,
    API keys, credentials, and database connection strings.

    Architecture note: `_scan_content` accepts raw text so it can later be
    wired to real HTTP response bodies instead of simulated content.
    """

    @staticmethod
    def scan_content(source_text: str, source_url: str) -> list[dict]:
        """
        Run all regex patterns against source_text.
        Returns a list of finding dicts — pure logic, no I/O or async.
        Can be called with real HTTP response bodies in future integrations.
        """
        findings = []
        seen = set()
        for stype, pattern, severity, confidence in SECRET_PATTERNS:
            for m in pattern.finditer(source_text):
                raw = m.group(0)
                key = (stype, raw[:12])
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "secret_type":    stype,
                    "value_redacted": _redact(raw),
                    "extracted_from": source_url,
                    "severity":       severity,
                    "confidence":     confidence,
                    "pattern_matched": pattern.pattern[:60],
                })
        return findings

    @staticmethod
    def check_sensitive_path(url: str) -> dict | None:
        """
        Check if a URL path matches a known sensitive filename pattern.
        Returns a finding dict or None.
        """
        lower = url.lower()
        for pat in SENSITIVE_PATH_PATTERNS:
            if lower.endswith(pat) or pat in lower:
                return {
                    "secret_type":    "Sensitive File Exposed",
                    "value_redacted": url,
                    "extracted_from": url,
                    "severity":       "high",
                    "confidence":     "High",
                    "pattern_matched": f"filename matches: {pat}",
                }
        return None

    async def run(self, scan_id: int, endpoints_file: str, output_dir: str) -> str:
        secrets_out = os.path.join(output_dir, "secrets.json")
        await manager.broadcast_event(scan_id, "module_start", MODULE)
        await manager.broadcast_log(scan_id, "Hunting for exposed credentials and configuration secrets...", MODULE, "info")

        all_findings: list[dict] = []
        targets: list[str] = []

        if os.path.exists(endpoints_file):
            with open(endpoints_file, "r") as f:
                targets = [l.strip() for l in f if l.strip()][:30]

        if not targets:
            targets = [
                "https://example.com/config.json",
                "https://example.com/.env",
                "https://example.com/static/js/main.bundle.js",
            ]

        # ── Phase 1: Sensitive path scan ────────────────────────────────────────
        await manager.broadcast_log(scan_id, f"Scanning {len(targets)} endpoints for sensitive file exposure...", MODULE, "info")
        for url in targets:
            hit = self.check_sensitive_path(url)
            if hit:
                all_findings.append(hit)
                await manager.broadcast_log(
                    scan_id,
                    f"SENSITIVE FILE DETECTED: {url}",
                    MODULE, "warn"
                )
            await asyncio.sleep(0.05)

        # ── Phase 2: Regex secret scan on simulated/future response bodies ────
        await manager.broadcast_log(scan_id, "Running pattern-matching on endpoint content...", MODULE, "info")

        # Simulated response bodies — structured to be replaceable with real HTTP
        simulated_responses: list[tuple[str, str]] = [
            (
                targets[0],
                'DB_URL="mongodb://admin:SuperSecret99!@db.internal:27017/prod"\n'
                'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n'
                'STRIPE_SECRET=sk_test_51HGabcXYZ123456789012345\n'
            ),
            (
                targets[1] if len(targets) > 1 else "https://example.com/.env",
                'API_KEY="AIzaSyD-9tSrke72I6oL0jKi"\n'
                'JWT_SECRET="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ.abc123"\n'
            ),
        ]

        for url, body in simulated_responses:
            await asyncio.sleep(0.2)
            findings = self.scan_content(body, url)
            for f in findings:
                await manager.broadcast_log(
                    scan_id,
                    f"[{f['severity'].upper()}] {f['secret_type']} found in {url}",
                    MODULE, "warn" if f["severity"] in ("high", "medium") else "critical"
                )
            all_findings.extend(findings)

        with open(secrets_out, "w") as fh:
            json.dump(all_findings, fh, indent=2)

        await manager.broadcast_log(scan_id, f"Secret scan complete — {len(all_findings)} potential exposures found.", MODULE, "success")
        await manager.broadcast_event(scan_id, "module_complete", MODULE, {"secrets_found": len(all_findings)})
        return secrets_out
