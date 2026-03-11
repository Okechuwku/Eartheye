FREE_ROLE = "Free"
PREMIUM_ROLE = "Premium"
ADMIN_ROLE = "Administrator"

ROLE_LABELS = {
    FREE_ROLE: "Free user",
    PREMIUM_ROLE: "Premium user ($25 plan)",
    ADMIN_ROLE: "Administrator",
}

SCAN_TYPES = {
    "Basic Scan",
    "Recon Scan",
    "Full Scan",
}

SCAN_FEATURES = {
    "Basic Scan": ["subfinder", "httpx"],
    "Recon Scan": [
        "subfinder",
        "httpx",
        "katana",
        "gau",
        "javascript_intelligence",
        "graphql",
    ],
    "Full Scan": [
        "subfinder",
        "httpx",
        "katana",
        "gau",
        "javascript_intelligence",
        "graphql",
        "ffuf",
        "nuclei",
    ],
}


def normalize_role(role: str | None) -> str:
    value = (role or FREE_ROLE).strip()
    lowered = value.lower()
    if lowered in {"user", "free", "free user"}:
        return FREE_ROLE
    if lowered in {"premium", "premium user", "premium user ($25 plan)"}:
        return PREMIUM_ROLE
    if lowered in {"admin", "administrator"}:
        return ADMIN_ROLE
    return value



def subscription_plan_for_role(role: str | None) -> str:
    normalized = normalize_role(role)
    return ROLE_LABELS.get(normalized, normalized)



def is_admin_role(role: str | None) -> bool:
    return normalize_role(role) == ADMIN_ROLE



def is_premium_role(role: str | None) -> bool:
    return normalize_role(role) in {PREMIUM_ROLE, ADMIN_ROLE}



def can_run_scan(role: str | None, scan_type: str) -> bool:
    normalized = normalize_role(role)
    if scan_type not in SCAN_TYPES:
        return False
    if normalized == FREE_ROLE:
        return scan_type == "Basic Scan"
    return True



def can_manage_automation(role: str | None) -> bool:
    return is_premium_role(role)



def features_for_scan(role: str | None, scan_type: str) -> set[str]:
    normalized = normalize_role(role)
    base_features = set(SCAN_FEATURES.get(scan_type, SCAN_FEATURES["Basic Scan"]))
    if normalized == FREE_ROLE:
        return set(SCAN_FEATURES["Basic Scan"])
    return base_features
