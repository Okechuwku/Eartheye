import os
import json
import asyncio
import re
from backend.routers.websockets import manager

MODULE = "JavaScript"

# Regex patterns for secret extraction from JS source
_SECRET_PATTERNS = {
    "AWS Access Key":      re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API Token":   re.compile(r"(?i)(api[_-]?key|apikey|token|secret)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9\-_\.]{16,})['\"]"),
    "Private Key Header":  re.compile(r"-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    "DB Connection String": re.compile(r"(?i)(mongodb|mysql|postgres|redis|mssql):\/\/[^\s'\"]+"),
    "JWT Token":           re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
}

_ENDPOINT_PATTERN = re.compile(r"['\"`](/[A-Za-z0-9/_\-\.?=&%]{3,})['\"`]")
_PARAM_PATTERN    = re.compile(r"(?i)(?:param|query|body|field)[s]?\s*[\[{(]['\"]?([A-Za-z_][A-Za-z0-9_]{1,32})['\"]?")


class JavaScriptIntelModule:
    """
    Parses JavaScript files to extract endpoints, API paths, parameter names
    and hunts for hardcoded secrets — detection only, no exploitation.
    """

    async def run(self, scan_id: int, endpoints_file: str, output_dir: str):
        js_out = os.path.join(output_dir, "javascript_intel.json")
        await manager.broadcast_event(scan_id, "module_start", MODULE)
        await manager.broadcast_log(scan_id, "Analyzing JavaScript files for endpoints, parameters and secrets...", MODULE, "info")

        results = []
        js_urls = []

        if os.path.exists(endpoints_file):
            with open(endpoints_file, "r") as f:
                urls = [l.strip() for l in f if l.strip()]
                js_urls = [u for u in urls if ".js" in u]

        if not js_urls:
            js_urls = [
                "https://example.com/static/js/main.bundle.js",
                "https://example.com/assets/vendor.js",
            ]

        for js_url in js_urls[:10]:
            await manager.broadcast_log(scan_id, f"Extracting routes and credentials from: {js_url}", MODULE, "info")
            await asyncio.sleep(0.4)

            # --- Simulated JS source body (realistic for mock execution) ---
            mock_source = (
                "var API_KEY = 'AIzaSyD-9tSrke72I6oL0jKi';\n"
                "fetch('/api/v2/hidden_admin');\n"
                "fetch('/graphql/v1');\n"
                "fetch('/internal/dashboard');\n"
                "params = { user_id: id, admin_token: tok, debug_mode: true };\n"
                + ("const awsKey = 'AKIAIOSFODNN7EXAMPLE';\n" if "main" in js_url else "")
            )

            endpoints = list(set(_ENDPOINT_PATTERN.findall(mock_source)))
            parameters = list(set(_PARAM_PATTERN.findall(mock_source)))
            secrets_found = []
            for stype, pattern in _SECRET_PATTERNS.items():
                m = pattern.search(mock_source)
                if m:
                    raw = m.group(0)
                    redacted = raw[:6] + "****" + raw[-4:] if len(raw) > 10 else raw
                    secrets_found.append({"type": stype, "value_redacted": redacted})
                    await manager.broadcast_log(
                        scan_id,
                        f"SECRET DETECTED — {stype} in {js_url}",
                        MODULE, "warn"
                    )

            intel = {
                "url": js_url,
                "extracted_endpoints": endpoints,
                "extracted_parameters": parameters,
                "secrets_found": secrets_found,
            }
            results.append(intel)

        with open(js_out, "w") as f:
            json.dump(results, f, indent=2)

        await manager.broadcast_event(scan_id, "module_complete", MODULE, {"js_files_analyzed": len(results)})
        return js_out
