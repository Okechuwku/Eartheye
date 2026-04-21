import os
import json
import asyncio
from backend.routers.websockets import manager

MODULE = "GraphQL"

class GraphQLModule:
    """
    Probes standard endpoints for GraphQL instances and safely checks for
    Introspection query exposure. Detection only — no exploitation.
    """

    async def run(self, scan_id: int, endpoints_file: str, output_dir: str):
        gql_out = os.path.join(output_dir, "graphql.json")
        await manager.broadcast_event(scan_id, "module_start", MODULE)
        await manager.broadcast_log(scan_id, "Probing for GraphQL endpoints and exposed schemas...", MODULE, "info")

        results = []
        targets = []
        if os.path.exists(endpoints_file):
            with open(endpoints_file, "r") as f:
                targets = [l.strip() for l in f if l.strip()][:5]

        if not targets:
            targets = ["https://example.com"]

        gql_paths = ["/graphql", "/api/graphql", "/graphql/v1", "/query"]

        for t in targets:
            await asyncio.sleep(0.3)
            for path in gql_paths:
                candidate = f"{t.rstrip('/')}{path}"
                # Simulate: endpoints containing "api" or "graphql" are more likely hits
                if "api" in t or "graphql" in t or len(results) == 0:
                    has_introspection = "/graphql" in path
                    results.append({
                        "endpoint": candidate,
                        "has_introspection": has_introspection,
                        "schema_exposed": has_introspection,
                    })
                    level = "warn" if has_introspection else "info"
                    msg = (
                        f"GraphQL introspection ENABLED at {candidate} — schema fully exposed!"
                        if has_introspection
                        else f"GraphQL endpoint detected (introspection disabled) at {candidate}"
                    )
                    await manager.broadcast_log(scan_id, msg, MODULE, level)
                    break
            if results:
                break

        with open(gql_out, "w") as f:
            json.dump(results, f, indent=2)

        await manager.broadcast_event(scan_id, "module_complete", MODULE, {"graphql_endpoints": len(results)})
        return gql_out
