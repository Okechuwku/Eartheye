import os
from .executor import SubprocessExecutor
from backend.routers.websockets import manager

MODULE = "SafeVuln"

class SafeVulnerabilityModule:
    """
    Executes Nuclei focusing exclusively on SAFE heuristics — detection and
    evidence collection only. No exploit automation or payload injection.
    Targets: BAC, IDOR indicators, SSRF exposure, misconfigurations, info disclosure.
    """

    def __init__(self, executor: SubprocessExecutor):
        self.executor = executor

    async def run(self, scan_id: int, endpoints_file: str, output_dir: str):
        vulns_out = os.path.join(output_dir, "vulnerabilities.json")
        await manager.broadcast_event(scan_id, "module_start", MODULE)
        await manager.broadcast_log(
            scan_id,
            "Launching Nuclei with safe misconfiguration and exposure heuristics...",
            MODULE, "info"
        )

        async def log_cb(msg: str, level: str):
            await manager.broadcast_log(scan_id, msg, MODULE, level)

        if os.path.exists(endpoints_file):
            # Safe tags only — no exploit, no injection, no aggressive probing
            cmd = [
                "nuclei",
                "-l", endpoints_file,
                "-tags", "misconfiguration,exposure,config,info,token",
                "-severity", "info,low,medium,high,critical",
                "-json-export", vulns_out,
                "-silent"
            ]
            await self.executor.run_command_stream(cmd, log_callback=log_cb, timeout=600, retries=1)
            await manager.broadcast_log(scan_id, "Nuclei scan completed. Parsing results...", MODULE, "success")
        else:
            await manager.broadcast_log(scan_id, "No endpoint list found — skipping vulnerability scan.", MODULE, "warn")

        await manager.broadcast_event(scan_id, "module_complete", MODULE)
        return vulns_out
