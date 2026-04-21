import os
from .executor import SubprocessExecutor
from backend.routers.websockets import manager

MODULE = "Discovery"

class DiscoveryModule:
    def __init__(self, executor: SubprocessExecutor):
        self.executor = executor

    async def run(self, scan_id: int, target_domain: str, output_dir: str):
        subdomains_out = os.path.join(output_dir, "subdomains.txt")
        endpoints_out = os.path.join(output_dir, "endpoints.txt")

        await manager.broadcast_event(scan_id, "module_start", MODULE)
        await manager.broadcast_log(scan_id, f"Launching subfinder on {target_domain}...", MODULE, "info")

        async def log_cb(msg: str, level: str):
            await manager.broadcast_log(scan_id, msg, MODULE, level)

        cmd_sub = ["subfinder", "-d", target_domain, "-o", subdomains_out, "-silent"]
        await self.executor.run_command_stream(cmd_sub, log_callback=log_cb, timeout=300, retries=1)

        sub_count = 0
        if os.path.exists(subdomains_out):
            with open(subdomains_out, "r") as f:
                sub_count = len([l for l in f.readlines() if l.strip()])
            await manager.broadcast_log(scan_id, f"Discovered {sub_count} subdomains.", MODULE, "success")

        await manager.broadcast_log(scan_id, "Starting HTTPX for alive host detection...", MODULE, "info")
        if os.path.exists(subdomains_out):
            cmd_http = ["httpx", "-l", subdomains_out, "-o", endpoints_out, "-silent"]
            await self.executor.run_command_stream(cmd_http, log_callback=log_cb, timeout=300, retries=1)
        else:
            cmd_http = ["httpx", "-u", target_domain, "-o", endpoints_out, "-silent"]
            await self.executor.run_command_stream(cmd_http, log_callback=log_cb, timeout=60, retries=1)

        ep_count = 0
        if os.path.exists(endpoints_out):
            with open(endpoints_out, "r") as f:
                ep_count = len([l for l in f.readlines() if l.strip()])
            await manager.broadcast_log(scan_id, f"Confirmed {ep_count} alive endpoints.", MODULE, "success")

        await manager.broadcast_event(scan_id, "module_complete", MODULE, {"subdomains": sub_count, "endpoints": ep_count})
        return subdomains_out, endpoints_out
