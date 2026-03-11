from sqlalchemy import text


SCHEMA_PATCHES = [
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_plan VARCHAR DEFAULT 'Free user'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS subscription_status VARCHAR DEFAULT 'active'",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS output_dir VARCHAR",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS report_path VARCHAR",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS graph_data JSON DEFAULT '{}'::json",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS summary JSON DEFAULT '{}'::json",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS started_at TIMESTAMP",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS completed_at TIMESTAMP",
    "ALTER TABLE scans ADD COLUMN IF NOT EXISTS monitoring_target_id INTEGER",
    "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS source VARCHAR DEFAULT 'subfinder'",
    "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS title VARCHAR",
    "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS ip_address VARCHAR",
    "ALTER TABLE subdomains ADD COLUMN IF NOT EXISTS technologies JSON DEFAULT '[]'::json",
    "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS host VARCHAR",
    "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS path VARCHAR",
    "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS source VARCHAR DEFAULT 'crawler'",
    "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS content_type VARCHAR",
    "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS discovered_from VARCHAR",
    "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS technologies JSON DEFAULT '[]'::json",
    "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS hidden_parameters JSON DEFAULT '[]'::json",
    "ALTER TABLE endpoints ADD COLUMN IF NOT EXISTS is_graphql BOOLEAN DEFAULT FALSE",
    "ALTER TABLE directories ADD COLUMN IF NOT EXISTS url VARCHAR",
    "ALTER TABLE directories ADD COLUMN IF NOT EXISTS status_code INTEGER",
    "ALTER TABLE directories ADD COLUMN IF NOT EXISTS source VARCHAR DEFAULT 'ffuf'",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS template_id VARCHAR",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS host VARCHAR",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS matched_at VARCHAR",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS evidence TEXT",
    "ALTER TABLE vulnerabilities ADD COLUMN IF NOT EXISTS raw_data JSON DEFAULT '{}'::json",
    """
    CREATE TABLE IF NOT EXISTS secret_findings (
        id SERIAL PRIMARY KEY,
        scan_id INTEGER REFERENCES scans(id),
        category VARCHAR,
        severity VARCHAR DEFAULT 'high',
        location VARCHAR,
        source_url VARCHAR,
        value_preview VARCHAR,
        confidence VARCHAR DEFAULT 'medium',
        raw_match TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS graphql_findings (
        id SERIAL PRIMARY KEY,
        scan_id INTEGER REFERENCES scans(id),
        endpoint VARCHAR,
        introspection_enabled BOOLEAN DEFAULT FALSE,
        schema_types INTEGER,
        notes TEXT,
        source VARCHAR DEFAULT 'graphql'
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS monitoring_targets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        domain VARCHAR,
        scan_type VARCHAR DEFAULT 'Recon Scan',
        interval_minutes INTEGER DEFAULT 720,
        enabled BOOLEAN DEFAULT TRUE,
        last_run_at TIMESTAMP,
        next_run_at TIMESTAMP,
        last_snapshot JSON DEFAULT '{}'::json,
        last_diff JSON DEFAULT '{}'::json,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """,
]


async def ensure_runtime_schema(connection):
    for statement in SCHEMA_PATCHES:
        await connection.execute(text(statement))
