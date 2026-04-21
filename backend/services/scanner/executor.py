import asyncio
import os
import json
from typing import Callable, Awaitable, Optional

class ToolExecutionError(Exception):
    pass

class SubprocessExecutor:
    """
    Executes real system binaries with timeouts, retries, and strict error handling.
    If a binary is absent or fails unexpectedly, it can optionally return mock
    scan data to prevent stalling the development mode.
    Outputs are streamed via a real-time callback instead of blocking.
    """

    def __init__(self, use_mock_fallback: bool = False):
        self.use_mock_fallback = use_mock_fallback
        
        # Ensure common Go binary locations are in PATH for web-app execution context
        env_path = os.environ.get("PATH", "")
        extra_paths = ["/root/go/bin", "/home/kali/go/bin", "/home/user/go/bin", "/usr/local/go/bin"]
        for p in extra_paths:
            if p not in env_path:
                env_path = f"{p}:{env_path}"
        os.environ["PATH"] = env_path

    async def run_command_stream(
        self, 
        cmd: list[str], 
        log_callback: Optional[Callable[[str, str], Awaitable[None]]] = None,
        timeout: int = 300,
        retries: int = 1
    ) -> tuple[int, str]:
        """
        Runs a command using asyncio subprocess.
        Streams stdout and stderr line-by-line to log_callback asynchronously.
        Returns: exit_code, stdout_content
        """
        attempt = 0
        while attempt <= retries:
            attempt += 1
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout_lines = []
                
                async def read_stream(stream, is_stderr: bool):
                    buffer = ""
                    while True:
                        try:
                            # Read in chunks to prevent 'Line too long' limit errors
                            chunk = await stream.read(65536)
                        except Exception:
                            break
                        if not chunk:
                            break
                        
                        buffer += chunk.decode('utf-8', errors='replace')
                        while "\n" in buffer:
                            line, buffer = buffer.split("\n", 1)
                            decoded = line.rstrip()
                            if decoded:
                                if not is_stderr:
                                    stdout_lines.append(decoded)
                                if log_callback:
                                    level = "warn" if is_stderr else "info"
                                    # Basic heuristic JSON parsing to prevent massive logs
                                    log_msg = decoded
                                    if decoded.startswith('{'):
                                        try:
                                            data = json.loads(decoded)
                                            # Nuclei uses 'template-id' or 'info.name', katana uses 'request.endpoint', subfinder uses 'host'
                                            if 'host' in data: log_msg = data['host']
                                            elif 'info' in data and 'name' in data['info']: log_msg = data['info']['name']
                                            elif 'template-id' in data: log_msg = data['template-id']
                                            elif 'url' in data: log_msg = data['url']
                                        except:
                                            pass
                                    
                                    # Do not spam the websocket with thousands of lines per second
                                    # We only push a sample of the stream
                                    if len(stdout_lines) % 15 == 0 or is_stderr:
                                        await log_callback(log_msg[:150], level)

                try:
                    await asyncio.wait_for(
                        asyncio.gather(
                            read_stream(process.stdout, False),
                            read_stream(process.stderr, True),
                            process.wait()
                        ),
                        timeout=timeout
                    )
                    
                    if process.returncode != 0 and attempt <= retries:
                        if log_callback is not None:
                            await log_callback(f"Command failed with code {process.returncode}, retrying (attempt {attempt})...", "warn")
                        await asyncio.sleep(2)
                        continue
                        
                    return process.returncode or 1 if process.returncode != 0 else 0, "\n".join(stdout_lines)
                    
                except asyncio.TimeoutError:
                    try:
                        process.kill()
                    except:
                        pass
                    
                    # Ensure process is swept to prevent zombies
                    try:
                        await asyncio.wait_for(process.wait(), timeout=3.0)
                    except:
                        pass
                        
                    if attempt <= retries:
                        if log_callback is not None:
                            await log_callback(f"Command timed out, retrying (attempt {attempt})...", "warn")
                        continue
                    raise ToolExecutionError(f"Command {' '.join(cmd)} timed out after {timeout} seconds.")
                    
            except FileNotFoundError:
                if self.use_mock_fallback:
                    if log_callback is not None:
                        await log_callback(f"Binary {cmd[0]} not found in PATH. Gracefully falling back to simulation module.", "warn")
                    return await self._fallback_simulation(cmd, log_callback)
                else:
                    raise ToolExecutionError(f"Binary {cmd[0]} not found in PATH.")
            except Exception as e:
                if self.use_mock_fallback:
                    if log_callback is not None:
                        await log_callback(f"Unexpected execution error ({type(e).__name__}). Falling back to simulation.", "error")
                    return await self._fallback_simulation(cmd, log_callback)
                if attempt <= retries:
                    continue
                raise ToolExecutionError(f"Unexpected error executing {' '.join(cmd)}: {e}")
                
        raise ToolExecutionError(f"Command {' '.join(cmd)} failed after {retries} retries.")

    async def _fallback_simulation(self, cmd: list, log_callback=None) -> tuple[int, str]:
        """ Fallback simulation for unsupported local development environments """
        tool_name = cmd[0]
        if log_callback:
            await log_callback(f"Simulating {tool_name} execution...", "info")
            
        await asyncio.sleep(1) # simulate work
        
        if tool_name == "subfinder":
            target = cmd[cmd.index("-d") + 1] if "-d" in cmd else "example.com"
            out_file = cmd[cmd.index("-o") + 1] if "-o" in cmd else None
            subs = [f"api.{target}", f"dev.{target}", f"admin.{target}", f"vpn.{target}", f"graphql.{target}", f"staging.{target}"]
            if out_file:
                with open(out_file, "w") as f:
                    for s in subs:
                        f.write(s + "\n")
            return 0, "\n".join(subs)
            
        elif tool_name == "httpx":
            out_file = cmd[cmd.index("-o") + 1] if "-o" in cmd else None
            in_file = cmd[cmd.index("-l") + 1] if "-l" in cmd else None
            if out_file and in_file and os.path.exists(in_file):
                with open(out_file, "w") as out:
                    with open(in_file, "r") as inf:
                        for line in inf:
                            if "host" in line and "{" in line:
                                try:
                                    host = json.loads(line).get("host")
                                except:
                                    host = line.strip()
                            else:
                                host = line.strip()
                            if host:
                                out.write(f"https://{host}\n")
            return 0, ""
            
        elif tool_name == "katana":
            out_file = cmd[cmd.index("-o") + 1] if "-o" in cmd else None
            in_file = cmd[cmd.index("-list") + 1] if "-list" in cmd else None
            paths = ["/api/v1/health", "/admin/login", "/.git/config", "/graphql", "/assets/app.js", "/query", "/api/graphql", "/swagger-ui.html"]
            
            if out_file and in_file and os.path.exists(in_file):
                with open(out_file, "w") as out:
                    with open(in_file, "r") as inf:
                        for line in inf:
                            if "url" in line and "{" in line:
                                try:
                                    base_url = json.loads(line).get("url")
                                except:
                                    base_url = line.strip()
                            else:
                                base_url = line.strip()

                            if base_url:
                                for path in paths:
                                    out.write(f"{base_url}{path}\n")
            return 0, ""
            
        elif tool_name == "nuclei":
            out_file = cmd[cmd.index("-json-export") + 1] if "-json-export" in cmd else None
            in_file = cmd[cmd.index("-l") + 1] if "-l" in cmd else None
            vuln_templates = [
                {"name": "Broken Access Control (IDOR) on User Profiles", "severity": "high"},
                {"name": "Server-Side Request Forgery (SSRF) in Image Fetcher", "severity": "high"},
                {"name": "Exposed .git Directory on Staging Server", "severity": "high"},
                {"name": "Sensitive API Key Exposure in Client-Side JS Bundle", "severity": "critical"}
            ]
            if out_file and in_file and os.path.exists(in_file):
                vulns = []
                with open(in_file, "r") as inf:
                    lines = [l.strip() for l in inf.readlines() if l.strip()]
                    import random
                    num_vulns = min(len(lines), random.randint(3, 5))
                    vuln_targets = random.sample(lines, num_vulns) if num_vulns > 0 else []
                    
                    for target_url in vuln_targets:
                        # try to extract url from httpx/katana json
                        try:
                            t = json.loads(target_url).get("url", json.loads(target_url).get("request", {}).get("endpoint", target_url))
                        except:
                            t = target_url
                        
                        template = random.choice(vuln_templates)
                        vulns.append({
                            "info": {"severity": template["severity"], "name": template["name"]},
                            "matched-at": t
                        })
                        
                with open(out_file, "w") as out:
                    for v in vulns:
                        out.write(json.dumps(v) + "\n")
            return 0, ""
            
        return 0, "Fallback triggered"
