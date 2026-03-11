from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str


class SubscriptionUpdate(BaseModel):
    role: str
    subscription_status: str = "active"

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    role: str
    subscription_plan: str = "Free user"
    subscription_status: str = "active"

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class ScanCreate(BaseModel):
    target_domain: str
    scan_type: str


class AutomationBatchCreate(BaseModel):
    domains: List[str] = Field(default_factory=list)
    scan_type: str = "Recon Scan"
    interval_minutes: int = 720


class AutomationTargetUpdate(BaseModel):
    enabled: bool

class ScanResponse(BaseModel):
    id: int
    target_domain: str
    status: str
    scan_type: str
    created_at: datetime
    output_dir: Optional[str] = None
    report_path: Optional[str] = None
    summary: Dict[str, Any] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True


class SubdomainResponse(BaseModel):
    id: int
    domain: str
    is_alive: bool
    source: str
    title: Optional[str] = None
    ip_address: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)

    class Config:
        from_attributes = True


class EndpointResponse(BaseModel):
    id: int
    url: str
    host: Optional[str] = None
    path: Optional[str] = None
    status_code: Optional[int] = None
    method: Optional[str] = None
    source: str
    content_type: Optional[str] = None
    discovered_from: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    hidden_parameters: List[str] = Field(default_factory=list)
    is_graphql: bool = False

    class Config:
        from_attributes = True


class DirectoryResponse(BaseModel):
    id: int
    path: str
    url: Optional[str] = None
    status_code: Optional[int] = None
    source: str

    class Config:
        from_attributes = True


class VulnerabilityResponse(BaseModel):
    id: int
    severity: str
    description: str
    tool: str
    template_id: Optional[str] = None
    host: Optional[str] = None
    matched_at: Optional[str] = None
    evidence: Optional[str] = None
    raw_data: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class SecretFindingResponse(BaseModel):
    id: int
    category: str
    severity: str
    location: str
    source_url: Optional[str] = None
    value_preview: Optional[str] = None
    confidence: str
    raw_match: Optional[str] = None

    class Config:
        from_attributes = True


class GraphQLFindingResponse(BaseModel):
    id: int
    endpoint: str
    introspection_enabled: bool
    schema_types: Optional[int] = None
    notes: Optional[str] = None
    source: str

    class Config:
        from_attributes = True


class MonitoringTargetResponse(BaseModel):
    id: int
    domain: str
    scan_type: str
    interval_minutes: int
    enabled: bool
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    last_snapshot: Dict[str, Any] = Field(default_factory=dict)
    last_diff: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    class Config:
        from_attributes = True


class ScanResultsResponse(BaseModel):
    scan: ScanResponse
    subdomains: List[SubdomainResponse] = Field(default_factory=list)
    endpoints: List[EndpointResponse] = Field(default_factory=list)
    directories: List[DirectoryResponse] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityResponse] = Field(default_factory=list)
    secrets: List[SecretFindingResponse] = Field(default_factory=list)
    graphql_findings: List[GraphQLFindingResponse] = Field(default_factory=list)
    graph_data: Dict[str, Any] = Field(default_factory=dict)
    summary: Dict[str, Any] = Field(default_factory=dict)
    report_download_url: Optional[str] = None


class AdminOverviewResponse(BaseModel):
    total_users: int
    total_scans: int
    total_vulnerabilities: int
    total_secrets: int
    premium_users: int
    active_monitors: int
