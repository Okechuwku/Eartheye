import os
import asyncio
from playwright.async_api import async_playwright
from backend.routers.websockets import manager

MODULE = "Screenshots"

class ScreenshotModule:
    """ Captures 800x600 headless screenshots of alive HTTP endpoints. """
    
    async def run(self, scan_id: int, endpoints_file: str, output_dir: str):
        screenshots_dir = os.path.join(output_dir, "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)
        
        await manager.broadcast_event(scan_id, "module_start", MODULE)
        await manager.broadcast_log(scan_id, "Starting background visual triage engine...", MODULE, "info")

        if not os.path.exists(endpoints_file):
            await manager.broadcast_log(scan_id, "No endpoints to screenshot.", MODULE, "warn")
            await manager.broadcast_event(scan_id, "module_complete", MODULE)
            return screenshots_dir

        # Read endpoints and cap at a max number to avoid hanging Playwright forever
        with open(endpoints_file, "r") as f:
            endpoints = [line.strip() for line in f if line.strip() and line.strip().startswith("http")]
            
        MAX_SCREENSHOTS = 15  # Limit set per user spec to avoid overload
        endpoints = endpoints[:MAX_SCREENSHOTS]
        
        if not endpoints:
            await manager.broadcast_log(scan_id, "No valid HTTP targets for screenshotting.", MODULE, "warn")
            await manager.broadcast_event(scan_id, "module_complete", MODULE)
            return screenshots_dir

        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context(
                    viewport={'width': 800, 'height': 600},
                    ignore_https_errors=True
                )
                
                captured = 0
                for ep in endpoints:
                    try:
                        safe_name = ep.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
                        outfile = os.path.join(screenshots_dir, f"{safe_name}.png")
                        
                        page = await context.new_page()
                        await page.goto(ep, timeout=12000, wait_until="load") # 12s max per page
                        await asyncio.sleep(1) # Extra second for JS render rendering
                        await page.screenshot(path=outfile)
                        await page.close()
                        captured += 1
                        if captured % 5 == 0:
                            await manager.broadcast_log(scan_id, f"Captured {captured}/{len(endpoints)} screenshots...", MODULE, "info")
                    except Exception as e:
                        try: await page.close()
                        except: pass
                        continue
                        
                await browser.close()
                await manager.broadcast_log(scan_id, f"Visual triage complete. Saved {captured} screenshots.", MODULE, "success")
                
        except Exception as e:
            await manager.broadcast_log(scan_id, f"Playwright engine failure (check dependencies): {e}", MODULE, "error")

        await manager.broadcast_event(scan_id, "module_complete", MODULE)
        return screenshots_dir
