import os
from .executor import SubprocessExecutor
from backend.routers.websockets import manager

MODULE = "Crawler"

class CrawlingModule:
    def __init__(self, executor: SubprocessExecutor):
        self.executor = executor

    async def run(self, scan_id: int, endpoints_file: str, output_dir: str):
        katana_out = os.path.join(output_dir, "katana_endpoints.txt")

        await manager.broadcast_event(scan_id, "module_start", MODULE)
        await manager.broadcast_log(scan_id, "Starting Katana depth crawler on discovered endpoints...", MODULE, "info")

        async def log_cb(msg: str, level: str):
            await manager.broadcast_log(scan_id, msg, MODULE, level)

        if os.path.exists(endpoints_file):
            cmd_crawler = ["katana", "-list", endpoints_file, "-o", katana_out, "-silent"]
            await self.executor.run_command_stream(cmd_crawler, log_callback=log_cb, timeout=600, retries=1)

            if os.path.exists(katana_out):
                with open(katana_out, "r") as fk:
                    new_data = [l for l in fk.readlines() if l.strip()]

                if new_data:
                    await manager.broadcast_log(scan_id, f"Discovered {len(new_data)} additional hidden paths.", MODULE, "success")
                    with open(endpoints_file, "a") as f:
                        f.writelines(new_data)

        await manager.broadcast_event(scan_id, "module_complete", MODULE)
        return katana_out
