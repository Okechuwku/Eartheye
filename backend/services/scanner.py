import asyncio
import json
import os
import re
import shutil
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urljoin, urlparse
from urllib.request import Request, urlopen

from sqlalchemy import delete
from sqlalchemy.future import select

from backend.database import AsyncSessionLocal
from backend.models import (
    Directory,
    Endpoint,
    GraphQLFinding,
    Scan,
    SecretFinding,
    Subdomain,
    User,
    Vulnerability,
)
from backend.routers.websockets import manager
from backend.services.automation import record_monitoring_snapshot
from backend.services.subscriptions import features_for_scan, normalize_role


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
SCANS_DIR = os.path.abspath(os.getenv("SCAN_STORAGE_PATH", os.path.join(PROJECT_ROOT, "scans")))
WORDLIST_PATH = os.path.join(PROJECT_ROOT, "backend", "services", "wordlists", "common.txt")
REQUIRED_OUTPUT_FILES = {
    "subdomains": "subdomains.txt",
    "endpoints": "endpoints.txt",
    "directories": "directories.txt",
    "vulnerabilities": "vulnerabilities.json",
}
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/query"]
INTROSPECTION_QUERY = "query IntrospectionQuery { __schema { types { name } queryType { name } mutationType { name } } }"
FALLBACK_MAX_SUBDOMAINS = 250
FALLBACK_MAX_URLS = 300

ROUTE_PATTERN = re.compile(r"[\"']((?:https?://[^\"'\s]+|/(?:[A-Za-z0-9_\-./?=&:{}]+)))[\"']")
PLACEHOLDER_PATTERN = re.compile(r"[:{]([A-Za-z0-9_\-]{2,64})[}]?")
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "critical"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "critical"),
    ("JWT token", re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"), "high"),
    ("OAuth token", re.compile(r"ya29\.[0-9A-Za-z\-_]+"), "high"),
    (
        "Generic API secret",
        re.compile(r"(?i)(?:api[_-]?key|secret|token|client_secret|access_token|authorization)[\"'\]\s:=]+([A-Za-z0-9_\-.=]{10,})"),
        "high",
    ),
]

TOOL_SEARCH_DIRS = [
    path
    for path in [
        "/usr/local/bin",
        "/usr/bin",
        "/bin",
        "/snap/bin",
        os.path.expanduser("~/.local/bin"),
        os.path.expanduser("~/go/bin"),
        "/home/azureuser/go/bin",
    ]
    if path
]


class ScanCollector:
    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.metadata: dict[str, object] = {}
        self.subdomains: dict[str, dict] = {}
        self.endpoints: dict[str, dict] = {}
        self.directories: dict[str, dict] = {}
        self.vulnerabilities: dict[str, dict] = {}
        self.secrets: dict[str, dict] = {}
        self.graphql_findings: dict[str, dict] = {}
        self.js_files: set[str] = set()
        self.technologies: set[str] = set()

    def add_subdomain(
        self,
        domain: str,
        *,
        is_alive: bool = False,
        source: str = "subfinder",
        title: str | None = None,
        ip_address: str | None = None,
        technologies: list[str] | None = None,
    ):
        value = (domain or "").strip().lower()
        if not value or value == self.target_domain:
            return
        entry = self.subdomains.get(
            value,
            {
                "domain": value,
                "is_alive": False,
                "source": source,
                "title": title,
                "ip_address": ip_address,
                "technologies": [],
            },
        )
        entry["is_alive"] = entry["is_alive"] or is_alive
        entry["source"] = entry["source"] or source
        entry["title"] = entry["title"] or title
        entry["ip_address"] = entry["ip_address"] or ip_address
        merged_tech = set(entry.get("technologies", []))
        merged_tech.update(clean_technologies(technologies))
        entry["technologies"] = sorted(merged_tech)
        self.technologies.update(entry["technologies"])
        self.subdomains[value] = entry

    def add_endpoint(
        self,
        url: str,
        *,
        source: str,
        status_code: int | None = None,
        method: str | None = None,
        content_type: str | None = None,
        discovered_from: str | None = None,
        technologies: list[str] | None = None,
        hidden_parameters: list[str] | None = None,
        is_graphql: bool = False,
    ):
        normalized = normalize_url(url, discovered_from, self.target_domain)
        if not normalized:
            return

        parsed = urlparse(normalized)
        host = parsed.netloc.lower()
        path = parsed.path or "/"
        params = {key for key, _ in parse_qsl(parsed.query, keep_blank_values=True)}
        params.update(hidden_parameters or [])

        entry = self.endpoints.get(
            normalized,
            {
                "url": normalized,
                "host": host,
                "path": path,
                "status_code": status_code,
                "method": method,
                "source": source,
                "content_type": content_type,
                "discovered_from": discovered_from,
                "technologies": [],
                "hidden_parameters": [],
                "is_graphql": is_graphql,
            },
        )
        if status_code is not None:
            entry["status_code"] = status_code
        entry["method"] = entry.get("method") or method
        entry["content_type"] = entry.get("content_type") or content_type
        entry["source"] = entry.get("source") or source
        entry["discovered_from"] = entry.get("discovered_from") or discovered_from
        entry["is_graphql"] = entry.get("is_graphql", False) or is_graphql
        merged_tech = set(entry.get("technologies", []))
        merged_tech.update(clean_technologies(technologies))
        entry["technologies"] = sorted(merged_tech)
        self.technologies.update(entry["technologies"])
        merged_params = set(entry.get("hidden_parameters", []))
        merged_params.update(value for value in params if value)
        entry["hidden_parameters"] = sorted(merged_params)
        self.endpoints[normalized] = entry

        if host.endswith(self.target_domain) and host != self.target_domain:
            self.add_subdomain(host, is_alive=True, source=source, technologies=entry["technologies"])

        if normalized.lower().endswith(".js"):
            self.js_files.add(normalized)

    def add_directory(self, path_or_url: str, *, source: str, status_code: int | None = None):
        normalized = normalize_url(path_or_url, None, self.target_domain)
        parsed = urlparse(normalized) if normalized else None
        path = parsed.path if parsed else (path_or_url.strip() or "/")
        key = normalized or path
        entry = self.directories.get(
            key,
            {
                "path": path,
                "url": normalized,
                "status_code": status_code,
                "source": source,
            },
        )
        if status_code is not None:
            entry["status_code"] = status_code
        self.directories[key] = entry

    def add_vulnerability(self, vuln: dict):
        key = "::".join(
            [
                vuln.get("tool", "unknown"),
                vuln.get("template_id") or vuln.get("description", "unknown"),
                vuln.get("matched_at") or vuln.get("host") or "scan",
            ]
        )
        self.vulnerabilities[key] = vuln

    def add_secret(self, secret: dict):
        key = "::".join([secret.get("category", "secret"), secret.get("location", "unknown"), secret.get("value_preview", "")])
        self.secrets[key] = secret

    def add_graphql(self, finding: dict):
        endpoint = finding.get("endpoint")
        if not endpoint:
            return
        self.graphql_findings[endpoint] = finding
        self.add_endpoint(endpoint, source=finding.get("source", "graphql"), is_graphql=True)

    def infer_directories_from_endpoints(self):
        for endpoint in self.endpoints.values():
            path = endpoint.get("path") or "/"
            if not path or path == "/":
                continue
            segments = [segment for segment in path.split("/") if segment]
            current = ""
            for segment in segments[:-1]:
                current += f"/{segment}"
                base_url = endpoint["url"].split(path, 1)[0] if path in endpoint["url"] else None
                directory_url = f"{base_url}{current}" if base_url else current
                self.add_directory(directory_url, source="inferred")

    def write_files(self, output_dir: str):
        ensure_output_dir(output_dir)
        write_lines(os.path.join(output_dir, REQUIRED_OUTPUT_FILES["subdomains"]), sorted(self.subdomains))
        write_lines(os.path.join(output_dir, REQUIRED_OUTPUT_FILES["endpoints"]), sorted(self.endpoints))
        directories = [entry.get("url") or entry.get("path") for entry in self.directories.values()]
        write_lines(os.path.join(output_dir, REQUIRED_OUTPUT_FILES["directories"]), sorted(filter(None, directories)))
        vuln_path = os.path.join(output_dir, REQUIRED_OUTPUT_FILES["vulnerabilities"])
        with open(vuln_path, "w", encoding="utf-8") as handle:
            json.dump(list(self.vulnerabilities.values()), handle, indent=2)

        json_outputs = {
            "javascript_intelligence.json": {
                "javascript_files": sorted(self.js_files),
                "endpoints": [endpoint for endpoint in self.endpoints.values() if endpoint.get("source") == "javascript"],
            },
            "secrets.json": list(self.secrets.values()),
            "graphql_findings.json": list(self.graphql_findings.values()),
            "summary.json": self.summary(),
        }
        for filename, payload in json_outputs.items():
            with open(os.path.join(output_dir, filename), "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)

    def summary(self) -> dict:
        severity_breakdown: dict[str, int] = {}
        for vulnerability in self.vulnerabilities.values():
            severity = (vulnerability.get("severity") or "unknown").lower()
            severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1

        summary = {
            "subdomains": len(self.subdomains),
            "endpoints": len(self.endpoints),
            "directories": len(self.directories),
            "vulnerabilities": len(self.vulnerabilities),
            "secrets": len(self.secrets),
            "graphql_findings": len(self.graphql_findings),
            "technologies": sorted(self.technologies),
            "javascript_files": sorted(self.js_files),
            "severity_breakdown": severity_breakdown,
        }
        if self.metadata:
            summary.update(self.metadata)
        return summary

    def build_graph(self) -> dict:
        nodes = [{"id": self.target_domain, "name": self.target_domain, "group": 1, "val": 18}]
        links = []
        node_ids = {self.target_domain}

        for subdomain in sorted(self.subdomains):
            if subdomain not in node_ids:
                nodes.append({"id": subdomain, "name": subdomain, "group": 2, "val": 13})
                node_ids.add(subdomain)
            links.append({"source": self.target_domain, "target": subdomain})

        for endpoint in self.endpoints.values():
            endpoint_id = endpoint["url"]
            if endpoint_id not in node_ids:
                nodes.append({"id": endpoint_id, "name": endpoint.get("path") or endpoint_id, "group": 3, "val": 9})
                node_ids.add(endpoint_id)

            parent = endpoint.get("host")
            if parent and parent in self.subdomains:
                links.append({"source": parent, "target": endpoint_id})
            else:
                links.append({"source": self.target_domain, "target": endpoint_id})

        for vulnerability in self.vulnerabilities.values():
            vuln_id = f"vuln::{vulnerability.get('template_id') or vulnerability.get('description')}::{vulnerability.get('matched_at') or vulnerability.get('host') or 'scan'}"
            if vuln_id not in node_ids:
                nodes.append({
                    "id": vuln_id,
                    "name": vulnerability.get("description", "vulnerability"),
                    "group": 4,
                    "val": 6,
                    "severity": vulnerability.get("severity", "unknown"),
                })
                node_ids.add(vuln_id)

            matched = vulnerability.get("matched_at") or vulnerability.get("host")
            parent_endpoint = find_best_endpoint(self.endpoints, matched)
            links.append({"source": parent_endpoint or self.target_domain, "target": vuln_id})

        return {"nodes": nodes, "links": dedupe_links(links)}

    def snapshot(self) -> dict:
        return {
            "subdomains": sorted(self.subdomains),
            "endpoints": sorted(self.endpoints),
            "directories": sorted(entry.get("url") or entry.get("path") for entry in self.directories.values()),
            "vulnerabilities": sorted(self.vulnerabilities),
            "secrets": sorted(self.secrets),
        }


def ensure_output_dir(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    for filename in REQUIRED_OUTPUT_FILES.values():
        file_path = os.path.join(output_dir, filename)
        if not os.path.exists(file_path):
            with open(file_path, "w", encoding="utf-8") as handle:
                if filename.endswith(".json"):
                    handle.write("[]")


def write_lines(file_path: str, lines: list[str]):
    with open(file_path, "w", encoding="utf-8") as handle:
        for line in sorted({value.strip() for value in lines if value and value.strip()}):
            handle.write(f"{line}\n")


def clean_technologies(values: list[str] | None) -> list[str]:
    cleaned = []
    for value in values or []:
        text = str(value).strip()
        if text:
            cleaned.append(text)
    return sorted(set(cleaned))


def normalize_url(url: str | None, discovered_from: str | None, target_domain: str) -> str | None:
    value = (url or "").strip()
    if not value:
        return None
    if value.startswith("//"):
        return f"https:{value}"
    if value.startswith("http://") or value.startswith("https://"):
        return value.rstrip()
    if value.startswith("/"):
        base = discovered_from or f"https://{target_domain}"
        return urljoin(base, value)
    if re.match(r"^[A-Za-z0-9_.-]+\.[A-Za-z]{2,}$", value):
        return f"https://{value}"
    return None


def dedupe_links(links: list[dict]) -> list[dict]:
    seen = set()
    unique_links = []
    for link in links:
        key = (link["source"], link["target"])
        if key in seen:
            continue
        seen.add(key)
        unique_links.append(link)
    return unique_links


def find_best_endpoint(endpoints: dict[str, dict], matched: str | None) -> str | None:
    if not matched:
        return None
    if matched in endpoints:
        return matched
    for endpoint_url in endpoints:
        if matched in endpoint_url:
            return endpoint_url
    return None


def build_tool_env() -> dict[str, str]:
    env = os.environ.copy()
    path_entries: list[str] = []
    seen: set[str] = set()
    for entry in TOOL_SEARCH_DIRS + env.get("PATH", "").split(os.pathsep):
        value = (entry or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        path_entries.append(value)
    env["PATH"] = os.pathsep.join(path_entries)
    return env


def resolve_command_path(command: str) -> str | None:
    if not command:
        return None
    if os.path.isabs(command):
        return command if os.path.exists(command) and os.access(command, os.X_OK) else None
    return shutil.which(command, path=build_tool_env().get("PATH", ""))


def command_exists(command: str) -> bool:
    return resolve_command_path(command) is not None


def collect_tool_paths(tool_names: list[str]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for tool_name in tool_names:
        tool_path = resolve_command_path(tool_name)
        if tool_path:
            resolved[tool_name] = tool_path
    return resolved


def normalize_scan_scope(target_domain: str) -> str:
    parts = [part for part in (target_domain or "").split(".") if part]
    if len(parts) >= 3 and parts[0] == "www":
        return ".".join(parts[1:])
    return target_domain


async def resolve_tool_status(features: set[str]) -> dict[str, str]:
    tool_status = {
        "subfinder": "available" if command_exists("subfinder") else "fallback-ctlogs",
        "httpx": "available" if await _check_go_httpx() else "fallback-native",
    }
    if "katana" in features:
        tool_status["katana"] = "available" if command_exists("katana") else "missing"
    if "gau" in features:
        tool_status["gau"] = "available" if command_exists("gau") else "missing"
    if "javascript_intelligence" in features:
        tool_status["linkfinder"] = "available" if command_exists("linkfinder") else "fallback-native"
    if "ffuf" in features:
        tool_status["ffuf"] = "available" if command_exists("ffuf") else "missing"
    if "nuclei" in features:
        tool_status["nuclei"] = "available" if command_exists("nuclei") else "missing"
    return tool_status


async def broadcast(scan_id: int, message: str):
    timestamp = datetime.utcnow().strftime("%H:%M:%S")
    try:
        await manager.broadcast_log(scan_id, f"[{timestamp}] {message}")
    except Exception:
        pass  # telemetry failures must never abort the scan


async def run_cmd_with_logs(scan_id: int, cmd: list[str], cwd: str, output_file: str | None = None) -> int:
    resolved_binary = resolve_command_path(cmd[0])
    if not resolved_binary:
        await broadcast(scan_id, f"[-] Tool unavailable: {cmd[0]}")
        return 127
    resolved_cmd = [resolved_binary, *cmd[1:]]
    try:
        process = await asyncio.create_subprocess_exec(
            *resolved_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd,
            env=build_tool_env(),
        )
    except FileNotFoundError:
        await broadcast(scan_id, f"[-] Tool unavailable: {cmd[0]}")
        return 127

    captured_lines = []
    while True:
        line = await process.stdout.readline()
        if not line:
            break
        decoded_line = line.decode("utf-8", errors="replace").strip()
        if decoded_line:
            captured_lines.append(decoded_line)
            await broadcast(scan_id, decoded_line)

    await process.wait()

    if output_file and captured_lines:
        with open(output_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(captured_lines))
            handle.write("\n")

    return process.returncode


async def http_request(url: str, *, method: str = "GET", headers: dict | None = None, data: bytes | None = None, timeout: int = 10):
    def _request():
        request = Request(url, data=data, headers=headers or {}, method=method)
        with urlopen(request, timeout=timeout) as response:
            return response.status, response.read().decode("utf-8", errors="replace"), response.headers.get("Content-Type")

    try:
        return await asyncio.to_thread(_request)
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body, exc.headers.get("Content-Type")
    except (URLError, TimeoutError, ValueError, OSError):
        # OSError catches socket errors (WinError 10054 - connection reset, etc.)
        return None, None, None


async def update_scan_status(scan_id: int, status: str, *, output_dir: str | None = None, report_path: str | None = None, graph_data: dict | None = None, summary: dict | None = None):
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalars().first()
        if not scan:
            return
        scan.status = status
        if output_dir is not None:
            scan.output_dir = output_dir
        if report_path is not None:
            scan.report_path = report_path
        if graph_data is not None:
            scan.graph_data = graph_data
        if summary is not None:
            scan.summary = summary
        if status == "Running" and not scan.started_at:
            scan.started_at = datetime.utcnow()
        if status in {"Completed", "Failed"}:
            scan.completed_at = datetime.utcnow()
        await db.commit()


async def persist_results(scan_id: int, collector: ScanCollector, output_dir: str, report_path: str):
    graph_data = collector.build_graph()
    summary = collector.summary()

    async with AsyncSessionLocal() as db:
        for model in [GraphQLFinding, SecretFinding, Vulnerability, Directory, Endpoint, Subdomain]:
            await db.execute(delete(model).where(model.scan_id == scan_id))

        db.add_all(
            [
                Subdomain(
                    scan_id=scan_id,
                    domain=entry["domain"],
                    is_alive=entry["is_alive"],
                    source=entry["source"],
                    title=entry.get("title"),
                    ip_address=entry.get("ip_address"),
                    technologies=entry.get("technologies", []),
                )
                for entry in collector.subdomains.values()
            ]
        )
        db.add_all(
            [
                Endpoint(
                    scan_id=scan_id,
                    url=entry["url"],
                    host=entry.get("host"),
                    path=entry.get("path"),
                    status_code=entry.get("status_code"),
                    method=entry.get("method"),
                    source=entry.get("source", "crawler"),
                    content_type=entry.get("content_type"),
                    discovered_from=entry.get("discovered_from"),
                    technologies=entry.get("technologies", []),
                    hidden_parameters=entry.get("hidden_parameters", []),
                    is_graphql=entry.get("is_graphql", False),
                )
                for entry in collector.endpoints.values()
            ]
        )
        db.add_all(
            [
                Directory(
                    scan_id=scan_id,
                    path=entry["path"],
                    url=entry.get("url"),
                    status_code=entry.get("status_code"),
                    source=entry.get("source", "ffuf"),
                )
                for entry in collector.directories.values()
            ]
        )
        db.add_all(
            [
                Vulnerability(
                    scan_id=scan_id,
                    severity=entry.get("severity", "unknown"),
                    description=entry.get("description", "Unknown finding"),
                    tool=entry.get("tool", "nuclei"),
                    template_id=entry.get("template_id"),
                    host=entry.get("host"),
                    matched_at=entry.get("matched_at"),
                    evidence=entry.get("evidence"),
                    raw_data=entry.get("raw_data", {}),
                )
                for entry in collector.vulnerabilities.values()
            ]
        )
        db.add_all(
            [
                SecretFinding(
                    scan_id=scan_id,
                    category=entry.get("category", "secret"),
                    severity=entry.get("severity", "high"),
                    location=entry.get("location", "javascript"),
                    source_url=entry.get("source_url"),
                    value_preview=entry.get("value_preview"),
                    confidence=entry.get("confidence", "medium"),
                    raw_match=entry.get("raw_match"),
                )
                for entry in collector.secrets.values()
            ]
        )
        db.add_all(
            [
                GraphQLFinding(
                    scan_id=scan_id,
                    endpoint=entry.get("endpoint"),
                    introspection_enabled=entry.get("introspection_enabled", False),
                    schema_types=entry.get("schema_types"),
                    notes=entry.get("notes"),
                    source=entry.get("source", "graphql"),
                )
                for entry in collector.graphql_findings.values()
            ]
        )

        result = await db.execute(select(Scan).where(Scan.id == scan_id))
        scan = result.scalars().first()
        if scan:
            scan.output_dir = output_dir
            scan.report_path = report_path
            scan.graph_data = graph_data
            scan.summary = summary
            scan.status = "Completed"
            scan.completed_at = datetime.utcnow()

        await db.commit()

    return graph_data, summary


# ---------------------------------------------------------------------------
# Tool-availability helpers
# ---------------------------------------------------------------------------

_GO_HTTPX_AVAILABLE: bool | None = None  # cached per-process check


async def _check_go_httpx() -> bool:
    """Return True only if the 'httpx' binary in PATH is the Go/ProjectDiscovery edition.

    The Python httpx package also installs an 'httpx' entry-point that accepts
    completely different flags; running it with ProjectDiscovery flags silently
    fails.  We verify by checking version output first, then fall back to
    inspecting the binary's ELF magic bytes (compiled Go binary vs Python script).
    """
    global _GO_HTTPX_AVAILABLE
    if _GO_HTTPX_AVAILABLE is not None:
        return _GO_HTTPX_AVAILABLE
    httpx_path = resolve_command_path("httpx")
    if not httpx_path:
        _GO_HTTPX_AVAILABLE = False
        return False
    try:
        # Try both -version and --version (flag varies across releases)
        for flag in ("-version", "--version"):
            proc = await asyncio.create_subprocess_exec(
                httpx_path, flag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env=build_tool_env(),
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
            output = stdout.decode("utf-8", errors="replace").lower()
            if "projectdiscovery" in output or (
                "current version" in output and "python" not in output
            ):
                _GO_HTTPX_AVAILABLE = True
                return True

        # Version flags gave no useful output — check ELF magic.
        # A compiled Go binary starts with 0x7f 'E' 'L' 'F'; a Python script
        # starts with '#!' or is plain text.
        if httpx_path:
            with open(httpx_path, "rb") as fh:
                magic = fh.read(4)
            if magic == b"\x7fELF":
                _GO_HTTPX_AVAILABLE = True
                return True

        _GO_HTTPX_AVAILABLE = False
    except Exception:
        _GO_HTTPX_AVAILABLE = False
    return _GO_HTTPX_AVAILABLE


async def _probe_http_native(scan_id: int, target_domain: str, collector: ScanCollector):
    """Probe target with Python's built-in HTTP client (Go httpx fallback)."""
    title_re = re.compile(r"<title[^>]*>([^<]*)</title>", re.IGNORECASE)
    for scheme in ("https", "http"):
        url = f"{scheme}://{target_domain}"
        status_code, body, content_type = await http_request(url, headers={"User-Agent": "Mozilla/5.0 Eartheye/1.0"})
        if status_code is None:
            continue
        title = None
        if body:
            m = title_re.search(body)
            if m:
                title = m.group(1).strip()[:120]
        collector.add_endpoint(url, source="httpx", status_code=status_code, content_type=content_type)
        suffix = f" [{title}]" if title else ""
        await broadcast(scan_id, f"[+] {url} [{status_code}]{suffix}")


def _normalize_subdomain_candidate(candidate: str, target_domain: str) -> str | None:
    value = (candidate or "").strip().lower()
    if not value:
        return None
    if value.startswith("*."):
        value = value[2:]
    value = value.split(":", 1)[0].strip(".")
    if value == target_domain:
        return None
    if not value.endswith(f".{target_domain}"):
        return None
    if not re.match(r"^[a-z0-9.-]+$", value):
        return None
    return value


async def _fallback_subfinder(scan_id: int, target_domain: str, collector: ScanCollector):
    await broadcast(scan_id, "[*] Built-in subdomain discovery running in minimal mode")
    status_code, body, _ = await http_request(
        f"https://crt.sh/?q=%25.{target_domain}&output=json",
        headers={"User-Agent": "Eartheye/1.0"},
        timeout=20,
    )
    if status_code != 200 or not body:
        await broadcast(scan_id, "[*] Certificate transparency lookup returned no data")
        return

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        await broadcast(scan_id, "[*] Certificate transparency lookup returned invalid JSON")
        return

    discovered: set[str] = set()
    for entry in payload if isinstance(payload, list) else []:
        for candidate in str(entry.get("name_value", "")).splitlines():
            normalized = _normalize_subdomain_candidate(candidate, target_domain)
            if normalized:
                discovered.add(normalized)
                if len(discovered) >= FALLBACK_MAX_SUBDOMAINS:
                    break
        if len(discovered) >= FALLBACK_MAX_SUBDOMAINS:
            break

    for subdomain in sorted(discovered):
        collector.add_subdomain(subdomain, is_alive=False, source="crt.sh")

    if discovered:
        await broadcast(scan_id, f"[+] Built-in subdomain discovery collected {len(discovered)} entries from CT logs")
    else:
        await broadcast(scan_id, "[*] No subdomains found in CT logs for target scope")


async def _fallback_gau(scan_id: int, target_domain: str, collector: ScanCollector):
    await broadcast(scan_id, "[*] Built-in passive URL discovery running in minimal mode")


async def run_subfinder(scan_id: int, target_domain: str, output_dir: str, collector: ScanCollector):
    output_file = os.path.join(output_dir, "subdomains.txt")
    await broadcast(scan_id, "[+] Running subfinder")
    if command_exists("subfinder"):
        await run_cmd_with_logs(scan_id, ["subfinder", "-d", target_domain, "-silent", "-o", output_file], output_dir)
    else:
        await broadcast(scan_id, "[*] Using built-in subdomain discovery")
        await _fallback_subfinder(scan_id, target_domain, collector)

    if os.path.exists(output_file):
        with open(output_file, "r", encoding="utf-8") as handle:
            for line in handle:
                subdomain = line.strip()
                if subdomain:
                    collector.add_subdomain(subdomain, is_alive=False, source="subfinder")
                    await broadcast(scan_id, f"[+] Found {subdomain}")


async def run_httpx(scan_id: int, target_domain: str, output_dir: str, collector: ScanCollector):
    httpx_raw = os.path.join(output_dir, "httpx.jsonl")
    inputs_file = os.path.join(output_dir, "subdomains.txt")
    await broadcast(scan_id, "[+] Running httpx")

    if await _check_go_httpx():
        cmd = ["httpx", "-silent", "-json", "-title", "-tech-detect", "-status-code", "-o", httpx_raw]
        if os.path.exists(inputs_file) and os.path.getsize(inputs_file) > 0:
            cmd.extend(["-l", inputs_file])
        else:
            cmd.extend(["-u", target_domain])
        await run_cmd_with_logs(scan_id, cmd, output_dir)
    else:
        await broadcast(scan_id, "[*] httpx (Go) not found in PATH; using native HTTP probe")
        await _probe_http_native(scan_id, target_domain, collector)

    if os.path.exists(httpx_raw):
        with open(httpx_raw, "r", encoding="utf-8") as handle:
            for line in handle:
                payload = line.strip()
                if not payload:
                    continue
                try:
                    data = json.loads(payload)
                except json.JSONDecodeError:
                    continue
                url = data.get("url") or data.get("input")
                technologies = data.get("technologies") or data.get("tech") or []
                collector.add_endpoint(
                    url,
                    source="httpx",
                    status_code=data.get("status_code"),
                    content_type=data.get("content_type"),
                    technologies=technologies,
                )
                parsed = urlparse(url) if url else None
                host = parsed.netloc.lower() if parsed else None
                if host and host.endswith(target_domain) and host != target_domain:
                    collector.add_subdomain(
                        host,
                        is_alive=True,
                        source="httpx",
                        title=data.get("title"),
                        technologies=technologies,
                    )


async def run_katana(scan_id: int, output_dir: str, collector: ScanCollector):
    live_targets = [url for url, entry in collector.endpoints.items() if entry.get("source") in {"httpx", "seed"}]
    if not live_targets:
        return

    targets_file = os.path.join(output_dir, "httpx_targets.txt")
    katana_out = os.path.join(output_dir, "katana_urls.txt")
    write_lines(targets_file, live_targets)
    await broadcast(scan_id, "[+] Running katana crawler")

    if command_exists("katana"):
        await run_cmd_with_logs(scan_id, ["katana", "-list", targets_file, "-silent", "-o", katana_out], output_dir)
    else:
        await broadcast(scan_id, "[*] katana not found in PATH; skipping active crawl")
        return

    if os.path.exists(katana_out):
        with open(katana_out, "r", encoding="utf-8") as handle:
            for line in handle:
                url = line.strip()
                if not url:
                    continue
                collector.add_endpoint(url, source="katana")


async def run_gau(scan_id: int, target_domain: str, output_dir: str, collector: ScanCollector):
    gau_out = os.path.join(output_dir, "gau_urls.txt")
    await broadcast(scan_id, "[+] Running gau")

    if command_exists("gau"):
        await run_cmd_with_logs(scan_id, ["gau", "--subs", target_domain], output_dir, output_file=gau_out)
    else:
        await broadcast(scan_id, "[*] Using built-in passive URL discovery")
        await _fallback_gau(scan_id, target_domain, collector)
        return

    if os.path.exists(gau_out):
        with open(gau_out, "r", encoding="utf-8") as handle:
            for line in handle:
                url = line.strip()
                if not url:
                    continue
                collector.add_endpoint(url, source="gau")


async def run_linkfinder(scan_id: int, output_dir: str, collector: ScanCollector):
    if not collector.js_files:
        await broadcast(scan_id, "[+] No JavaScript assets discovered for LinkFinder analysis")
        return

    raw_file = os.path.join(output_dir, "linkfinder_raw.txt")
    await broadcast(scan_id, "[+] Running LinkFinder-compatible JavaScript analysis")

    if command_exists("linkfinder"):
        with open(raw_file, "w", encoding="utf-8") as handle:
            for js_url in sorted(collector.js_files):
                handle.write(f"# {js_url}\n")
                exit_code = await run_cmd_with_logs(scan_id, ["linkfinder", "-i", js_url, "-o", "cli"], output_dir)
                if exit_code not in {0, 127}:
                    await broadcast(scan_id, f"[-] LinkFinder returned {exit_code} for {js_url}")
    else:
        await broadcast(scan_id, "[*] LinkFinder binary not found; using built-in JavaScript intelligence parser")


async def analyze_javascript_assets(scan_id: int, collector: ScanCollector):
    if not collector.js_files:
        return

    await broadcast(scan_id, "[+] Extracting JavaScript endpoints")
    for js_url in sorted(collector.js_files):
        status_code, body, _ = await http_request(js_url, headers={"User-Agent": "Eartheye/1.0"})
        if status_code is None or not body:
            await broadcast(scan_id, f"[-] Unable to fetch JavaScript asset: {js_url}")
            continue

        endpoints_found = set()
        params_found = set()
        for raw_route in ROUTE_PATTERN.findall(body):
            normalized = normalize_url(raw_route, js_url, collector.target_domain)
            if not normalized:
                continue
            endpoints_found.add(normalized)
            parsed = urlparse(normalized)
            params_found.update(key for key, _ in parse_qsl(parsed.query, keep_blank_values=True))
            params_found.update(PLACEHOLDER_PATTERN.findall(parsed.path))

        for endpoint_url in sorted(endpoints_found):
            collector.add_endpoint(
                endpoint_url,
                source="javascript",
                discovered_from=js_url,
                hidden_parameters=sorted(params_found),
            )

        for category, pattern, severity in SECRET_PATTERNS:
            for match in pattern.finditer(body):
                raw_match = match.group(1) if match.groups() else match.group(0)
                collector.add_secret(
                    {
                        "category": category,
                        "severity": severity,
                        "location": js_url,
                        "source_url": js_url,
                        "value_preview": redact_secret(raw_match),
                        "confidence": "high",
                        "raw_match": raw_match,
                    }
                )

        await broadcast(scan_id, f"[+] Parsed {len(endpoints_found)} JavaScript endpoints from {js_url}")


def redact_secret(value: str) -> str:
    if len(value) <= 8:
        return value
    return f"{value[:4]}...{value[-4:]}"


async def run_graphql_discovery(scan_id: int, collector: ScanCollector):
    await broadcast(scan_id, "[+] Probing GraphQL endpoints")
    base_urls = {f"https://{collector.target_domain}", f"http://{collector.target_domain}"}
    base_urls.update(
        {
            f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for url in collector.endpoints
            if urlparse(url).scheme and urlparse(url).netloc
        }
    )

    for base_url in sorted(base_urls):
        for path_index, path in enumerate(GRAPHQL_PATHS):
            candidate = urljoin(base_url, path)
            status_code, body, content_type = await http_request(
                candidate,
                method="POST",
                headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "Eartheye/1.0"},
                data=json.dumps({"query": INTROSPECTION_QUERY}).encode("utf-8"),
            )
            if status_code is None or body is None:
                # Add small delay to avoid connection resets on rapid retries
                if path_index < len(GRAPHQL_PATHS) - 1:
                    await asyncio.sleep(0.2)
                continue

            # Only status codes that can plausibly come from a real GraphQL endpoint.
            # 404/301/302 etc. are almost certainly not GraphQL — skip them to
            # avoid false positives (e.g. Google 404 pages that contain the
            # path "/graphql" in their body text).
            if status_code not in {200, 400, 405, 422, 500}:
                continue

            introspection_enabled = False
            schema_types = None
            notes = None
            is_graphql = False
            try:
                payload = json.loads(body)
                schema = payload.get("data", {}).get("__schema")
                if schema:
                    introspection_enabled = True
                    schema_types = len(schema.get("types", []))
                    notes = "Schema introspection exposed"
                    is_graphql = True
                elif payload.get("errors"):
                    raw_errors = payload.get("errors") or []
                    if isinstance(raw_errors, list) and raw_errors:
                        first_msg = (
                            raw_errors[0].get("message") or ""
                            if isinstance(raw_errors[0], dict) else ""
                        ).lower()
                        graphql_keywords = (
                            "query", "syntax", "parse", "introspect",
                            "field", "type", "must provide", "operation",
                        )
                        if any(kw in first_msg for kw in graphql_keywords):
                            notes = "; ".join(
                                e.get("message", "GraphQL error")
                                for e in raw_errors
                                if isinstance(e, dict)
                            )
                            is_graphql = True
            except json.JSONDecodeError:
                lowered = body.lower()
                # Require phrases actually emitted by GraphQL servers, NOT just
                # the word "graphql" which appears in 404 pages that echo the URL.
                if not any(phrase in lowered for phrase in (
                    "must provide query string",
                    "graphql request must",
                    "provide the query param",
                )):
                    continue
                notes = "Endpoint responded with GraphQL-indicative content"
                is_graphql = True

            if not is_graphql:
                continue

            collector.add_graphql(
                {
                    "endpoint": candidate,
                    "introspection_enabled": introspection_enabled,
                    "schema_types": schema_types,
                    "notes": notes or f"HTTP {status_code}",
                    "source": "graphql",
                }
            )
            await broadcast(scan_id, f"[+] GraphQL endpoint detected: {candidate}")
            # Small delay to avoid overwhelming target with rapid requests
            await asyncio.sleep(0.5)
        # Delay between probing different base URLs to avoid connection resets
        await asyncio.sleep(0.3)


async def run_ffuf(scan_id: int, output_dir: str, collector: ScanCollector):
    await broadcast(scan_id, "[+] Running ffuf directory fuzzing")
    base_urls = sorted(
        {
            f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for url, entry in collector.endpoints.items()
            if entry.get("source") in {"httpx", "seed"}
        }
    )
    if not base_urls:
        base_urls = [f"https://{collector.target_domain}"]

    if not command_exists("ffuf"):
        await broadcast(scan_id, "[*] ffuf not found in PATH; inferring directories from discovered endpoints instead")
        collector.infer_directories_from_endpoints()
        return

    raw_results = []
    for index, base_url in enumerate(base_urls, start=1):
        output_file = os.path.join(output_dir, f"ffuf_{index}.json")
        exit_code = await run_cmd_with_logs(
            scan_id,
            [
                "ffuf",
                "-u",
                f"{base_url.rstrip('/')}/FUZZ",
                "-w",
                WORDLIST_PATH,
                "-of",
                "json",
                "-o",
                output_file,
                "-mc",
                "all",
            ],
            output_dir,
        )
        if exit_code == 127 or not os.path.exists(output_file):
            continue

        try:
            with open(output_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue

        for item in data.get("results", []):
            raw_results.append(item)
            collector.add_directory(item.get("url") or item.get("input", {}).get("FUZZ", "/"), source="ffuf", status_code=item.get("status"))

    if raw_results:
        with open(os.path.join(output_dir, "ffuf_results.json"), "w", encoding="utf-8") as handle:
            json.dump(raw_results, handle, indent=2)
    collector.infer_directories_from_endpoints()


async def run_nuclei(scan_id: int, output_dir: str, collector: ScanCollector):
    targets_file = os.path.join(output_dir, "endpoints.txt")
    nuclei_raw = os.path.join(output_dir, "nuclei.jsonl")
    await broadcast(scan_id, "[+] Running nuclei scan")

    if not command_exists("nuclei"):
        await broadcast(scan_id, "[*] nuclei not found in PATH; skipping vulnerability scan")
        return

    exit_code = await run_cmd_with_logs(scan_id, ["nuclei", "-l", targets_file, "-jsonl", "-o", nuclei_raw], output_dir)
    if exit_code == 127 or not os.path.exists(nuclei_raw):
        return

    count = 0
    with open(nuclei_raw, "r", encoding="utf-8") as handle:
        for line in handle:
            payload = line.strip()
            if not payload:
                continue
            try:
                data = json.loads(payload)
            except json.JSONDecodeError:
                continue
            info = data.get("info", {})
            collector.add_vulnerability(
                {
                    "severity": info.get("severity", "unknown"),
                    "description": info.get("name", "Unnamed finding"),
                    "tool": "nuclei",
                    "template_id": data.get("template-id"),
                    "host": data.get("host"),
                    "matched_at": data.get("matched-at") or data.get("url"),
                    "evidence": data.get("matcher-name") or data.get("extracted-results"),
                    "raw_data": data,
                }
            )
            count += 1

    await broadcast(scan_id, f"[+] {count} vulnerabilities detected")


def generate_report(target_domain: str, output_dir: str, collector: ScanCollector) -> str:
    report_path = os.path.join(output_dir, f"{target_domain}_full_recon.txt")
    summary = collector.summary()
    tool_status = summary.get("tool_status") or {}
    tool_paths = summary.get("tool_paths") or {}
    lines = [
        f"Eartheye Recon Report - {target_domain}",
        f"Generated: {datetime.utcnow().isoformat()}Z",
        f"Requested Target: {summary.get('requested_target', target_domain)}",
        f"Discovery Root: {summary.get('scan_scope', collector.target_domain)}",
        "",
        "=== Summary ===",
        f"Subdomains: {summary['subdomains']}",
        f"Endpoints: {summary['endpoints']}",
        f"Directories: {summary['directories']}",
        f"Vulnerabilities: {summary['vulnerabilities']}",
        f"Secrets: {summary['secrets']}",
        f"GraphQL Findings: {summary['graphql_findings']}",
        "",
        "=== Tool Status ===",
        *([f"{tool}: {status}" for tool, status in tool_status.items()] or ["No tool diagnostics recorded"]),
        "",
        "=== Tool Paths ===",
        *([f"{tool}: {path}" for tool, path in tool_paths.items()] or ["No tool paths resolved"]),
        "",
        "=== Technologies ===",
        *(summary["technologies"] or ["None detected"]),
        "",
        "=== Subdomains ===",
        *(sorted(collector.subdomains) or ["None discovered"]),
        "",
        "=== Endpoints ===",
        *(sorted(collector.endpoints) or ["None discovered"]),
        "",
        "=== Directories ===",
        *([entry.get("url") or entry.get("path") for entry in collector.directories.values()] or ["None discovered"]),
        "",
        "=== Vulnerabilities ===",
    ]

    if collector.vulnerabilities:
        for vulnerability in collector.vulnerabilities.values():
            lines.append(
                f"- [{(vulnerability.get('severity') or 'unknown').upper()}] {vulnerability.get('description')} ({vulnerability.get('matched_at') or vulnerability.get('host') or 'scan-wide'})"
            )
    else:
        lines.append("None detected")

    lines.extend(["", "=== Secrets Discovered ==="])
    if collector.secrets:
        for secret in collector.secrets.values():
            lines.append(
                f"- [{secret.get('severity', 'high').upper()}] {secret.get('category')} at {secret.get('location')} => {secret.get('value_preview')}"
            )
    else:
        lines.append("None detected")

    lines.extend(["", "=== GraphQL ==="])
    if collector.graphql_findings:
        for finding in collector.graphql_findings.values():
            lines.append(
                f"- {finding.get('endpoint')} | introspection={'enabled' if finding.get('introspection_enabled') else 'disabled'} | {finding.get('notes') or 'No notes'}"
            )
    else:
        lines.append("None detected")

    with open(report_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    return report_path


async def resolve_scan_user_role(scan_id: int, fallback_role: str | None) -> str:
    if fallback_role:
        return normalize_role(fallback_role)
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan, User).join(User, User.id == Scan.user_id).where(Scan.id == scan_id))
        row = result.first()
        if not row:
            return "Free"
        _, user = row
        return normalize_role(user.role)


async def run_scan(scan_id: int, target_domain: str, scan_type: str, user_role: str | None = None, monitoring_target_id: int | None = None):
    output_dir = os.path.join(SCANS_DIR, target_domain)
    collector: ScanCollector | None = None
    try:
        ensure_output_dir(output_dir)
        scope_domain = normalize_scan_scope(target_domain)
        collector = ScanCollector(scope_domain)

        seed_hosts = [target_domain]
        if scope_domain != target_domain:
            seed_hosts.append(scope_domain)
        for host in seed_hosts:
            collector.add_endpoint(f"https://{host}", source="seed")
            collector.add_endpoint(f"http://{host}", source="seed")

        role = await resolve_scan_user_role(scan_id, user_role)
        features = features_for_scan(role, scan_type)
        tool_status = await resolve_tool_status(features)
        tool_paths = collect_tool_paths(["subfinder", "httpx", "katana", "gau", "linkfinder", "ffuf", "nuclei"])
        collector.metadata.update(
            {
                "requested_target": target_domain,
                "scan_scope": scope_domain,
                "tool_status": tool_status,
                "tool_paths": tool_paths,
                "missing_tools": [tool for tool, status in tool_status.items() if status == "missing"],
                "fallback_tools": [tool for tool, status in tool_status.items() if str(status).startswith("fallback-")],
            }
        )

        await update_scan_status(scan_id, "Running", output_dir=output_dir)
        scope_note = f" | discovery root: {scope_domain}" if scope_domain != target_domain else ""
        await broadcast(scan_id, f"[*] Starting {scan_type} on {target_domain} ({role} tier){scope_note}")

        missing_tools = collector.metadata.get("missing_tools") or []
        if missing_tools:
            await broadcast(scan_id, f"[*] Missing external tools: {', '.join(missing_tools)}")

        await run_subfinder(scan_id, scope_domain, output_dir, collector)
        collector.write_files(output_dir)

        await run_httpx(scan_id, scope_domain, output_dir, collector)
        collector.write_files(output_dir)

        if "katana" in features:
            await run_katana(scan_id, output_dir, collector)
            collector.write_files(output_dir)

        if "gau" in features:
            await run_gau(scan_id, scope_domain, output_dir, collector)
            collector.write_files(output_dir)

        if "javascript_intelligence" in features:
            await run_linkfinder(scan_id, output_dir, collector)
            await analyze_javascript_assets(scan_id, collector)
            collector.write_files(output_dir)

        if "graphql" in features:
            await run_graphql_discovery(scan_id, collector)
            collector.write_files(output_dir)

        if "ffuf" in features:
            await run_ffuf(scan_id, output_dir, collector)
        else:
            collector.infer_directories_from_endpoints()
        collector.write_files(output_dir)

        if "nuclei" in features:
            await run_nuclei(scan_id, output_dir, collector)
            collector.write_files(output_dir)

        report_path = generate_report(target_domain, output_dir, collector)
        graph_data, summary = await persist_results(scan_id, collector, output_dir, report_path)
        await update_scan_status(scan_id, "Completed", output_dir=output_dir, report_path=report_path, graph_data=graph_data, summary=summary)

        diff = await record_monitoring_snapshot(monitoring_target_id, collector.snapshot())
        if diff:
            new_items = sum(len(value) for value in diff.values())
            await broadcast(scan_id, f"[+] Monitoring delta recorded: {new_items} new artifacts")

        await broadcast(scan_id, "[*] Results saved to database")
    except Exception as exc:
        import traceback
        error_detail = f"{type(exc).__name__}: {exc}"
        error_trace = traceback.format_exc()
        failure_summary = {"error": error_detail, "trace": error_trace}
        if collector is not None and collector.metadata:
            failure_summary.update(collector.metadata)
        await update_scan_status(scan_id, "Failed", output_dir=output_dir, summary=failure_summary)
        await broadcast(scan_id, f"[-] Scan failed: {error_detail}")


def trigger_scan_task(
    scan_id: int,
    target_domain: str,
    scan_type: str,
    user_role: str | None = None,
    monitoring_target_id: int | None = None,
):
    asyncio.create_task(run_scan(scan_id, target_domain, scan_type, user_role, monitoring_target_id))
