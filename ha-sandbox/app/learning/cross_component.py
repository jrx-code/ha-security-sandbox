"""L.5 — Cross-Component Intelligence.

Detect patterns that appear across multiple components — shared suspicious
dependencies, common network domains, unusual API usage clusters, and
components that deviate from the norm of their category.
"""

import json
import logging
import sqlite3
from collections import Counter

log = logging.getLogger(__name__)


def analyze_cross_component(conn: sqlite3.Connection) -> dict:
    """Analyze patterns across all scanned components.

    Returns a dict with:
        - shared_domains: network domains used by multiple components
        - shared_imports: unusual imports shared by multiple components
        - outlier_components: components that deviate significantly from norms
        - domain_clusters: groups of components connecting to same domains
    """
    rows = conn.execute(
        "SELECT domain, repo_url, imports, ha_apis, network_domains, "
        "py_files, js_files, total_lines "
        "FROM component_fingerprints "
        "ORDER BY created_at DESC"
    ).fetchall()

    if not rows:
        return {"message": "No fingerprint data available"}

    # Deduplicate: keep latest fingerprint per domain/repo
    seen = set()
    fingerprints = []
    for row in rows:
        key = row["domain"] or row["repo_url"]
        if key in seen:
            continue
        seen.add(key)
        fingerprints.append({
            "id": key,
            "imports": json.loads(row["imports"]),
            "ha_apis": json.loads(row["ha_apis"]),
            "network_domains": json.loads(row["network_domains"]),
            "py_files": row["py_files"],
            "js_files": row["js_files"],
            "total_lines": row["total_lines"],
        })

    if len(fingerprints) < 2:
        return {"message": "Need at least 2 scanned components for cross-analysis"}

    # 1. Shared network domains (domains used by 2+ components)
    domain_counter: Counter = Counter()
    domain_users: dict[str, list[str]] = {}
    for fp in fingerprints:
        for d in fp["network_domains"]:
            domain_counter[d] += 1
            domain_users.setdefault(d, []).append(fp["id"])
    shared_domains = [
        {"domain": d, "count": c, "components": domain_users[d]}
        for d, c in domain_counter.most_common()
        if c >= 2
    ]

    # 2. Unusual shared imports (non-stdlib imports used by 2+ components)
    stdlib = {
        "os", "sys", "json", "re", "logging", "pathlib", "typing", "datetime",
        "collections", "functools", "itertools", "math", "hashlib", "uuid",
        "asyncio", "time", "io", "copy", "abc", "enum", "dataclasses",
        "contextlib", "unittest", "http", "urllib", "ssl", "socket",
        "threading", "multiprocessing", "subprocess", "shutil", "tempfile",
        "configparser", "argparse", "textwrap", "string", "struct", "base64",
        "homeassistant", "voluptuous", "aiohttp",  # HA common deps
    }
    import_counter: Counter = Counter()
    import_users: dict[str, list[str]] = {}
    for fp in fingerprints:
        for imp in fp["imports"]:
            if imp not in stdlib:
                import_counter[imp] += 1
                import_users.setdefault(imp, []).append(fp["id"])
    shared_imports = [
        {"import": imp, "count": c, "components": import_users[imp]}
        for imp, c in import_counter.most_common()
        if c >= 2
    ]

    # 3. Outlier components (significantly larger/smaller than average)
    if len(fingerprints) >= 3:
        lines = [fp["total_lines"] for fp in fingerprints if fp["total_lines"] > 0]
        if lines:
            avg_lines = sum(lines) / len(lines)
            outliers = []
            for fp in fingerprints:
                if fp["total_lines"] > 0:
                    ratio = fp["total_lines"] / avg_lines if avg_lines else 0
                    if ratio > 3 or ratio < 0.1:
                        outliers.append({
                            "component": fp["id"],
                            "total_lines": fp["total_lines"],
                            "avg_lines": round(avg_lines),
                            "ratio": round(ratio, 2),
                            "direction": "larger" if ratio > 3 else "smaller",
                        })
        else:
            outliers = []
    else:
        outliers = []

    # 4. Suspicious patterns: components connecting to the same unusual domains
    suspicious_domains = {"pastebin.com", "hastebin.com", "transfer.sh", "ngrok.io",
                          "webhook.site", "requestbin.com", "pipedream.com"}
    suspicious_hits = [
        {"domain": d, "components": domain_users[d]}
        for d in domain_counter
        if any(s in d for s in suspicious_domains) and domain_counter[d] >= 1
    ]

    return {
        "total_components": len(fingerprints),
        "shared_domains": shared_domains[:20],
        "shared_imports": shared_imports[:20],
        "outlier_components": outliers,
        "suspicious_domains": suspicious_hits,
    }
