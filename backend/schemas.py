from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class SubscriptionUpdate(BaseModel):
    role: Literal["Free", "Premium", "Administrator"]
    subscription_status: str = "active"

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    role: str
    subscription_tier: str

    class Config:
        from_attributes = True

class UserTierUpdate(BaseModel):
    subscription_tier: str  # "Free" or "Premium"

class UserRoleUpdate(BaseModel):
    role: str               # "Admin" or "User"

class AdminStatsResponse(BaseModel):
    total_users: int
    premium_users: int
    total_scans: int
    total_vulnerabilities: int

class TargetCreate(BaseModel):
    domain: str
    project_name: str = "Default"

class TargetResponse(TargetCreate):
    id: int
    last_scan: Optional[datetime] = None
    total_subdomains: int = 0
    total_endpoints: int = 0
    total_vulnerabilities: int = 0
    risk_score: int = 0
    last_change_detected: Optional[datetime] = None

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class ScanCreate(BaseModel):
    target_domain: str = Field(min_length=3, max_length=253)
    scan_type: Literal["Basic Scan", "Recon Scan", "Full Scan"]


class AutomationBatchCreate(BaseModel):
    domains: List[str] = Field(default_factory=list)
    scan_type: Literal["Basic Scan", "Recon Scan", "Full Scan"] = "Recon Scan"
    interval_minutes: int = Field(default=720, ge=60, le=10080)


class AutomationTargetUpdate(BaseModel):
    enabled: bool

class ScanResponse(BaseModel):
    id: int
    target_domain: str
    status: str
    scan_type: str
    created_at: datetime
class SubdomainResponse(BaseModel):
    id: int
    domain: str
    is_alive: bool
    is_new: bool = False
    
    class Config:
        from_attributes = True

class EndpointResponse(BaseModel):
    id: int
    url: str
    status_code: Optional[int]
    method: Optional[str]
    is_new: bool = False
    
    class Config:
        from_attributes = True

class VulnerabilityResponse(BaseModel):
    id: int
    severity: str
    description: str
    tool: str
    confidence: str
    exposure_level: str
    priority: str
    manual_review_required: bool
    is_new: bool = False
    
    class Config:
        from_attributes = True

class TechnologyResponse(BaseModel):
    id: int
    name: str
    category: Optional[str] = None
    version: Optional[str] = None

    class Config:
        from_attributes = True

class GraphQLResponse(BaseModel):
    id: int
    endpoint: str
    has_introspection: bool

    class Config:
        from_attributes = True

class JavaScriptResponse(BaseModel):
    id: int
    url: str
    extracted_endpoints: Optional[str] = None
    extracted_parameters: Optional[str] = None

    class Config:
        from_attributes = True

class SecretResponse(BaseModel):
    id: int
    value: str
    extracted_from: str
    secret_type: str
    is_new: bool = False

    class Config:
        from_attributes = True

class DetailedScanResponse(ScanResponse):
    subdomains: List[SubdomainResponse] = []
    endpoints: List[EndpointResponse] = []
    vulnerabilities: List[VulnerabilityResponse] = []
    technologies: List[TechnologyResponse] = []
    graphql_endpoints: List[GraphQLResponse] = []
    javascript_files: List[JavaScriptResponse] = []
    secrets: List[SecretResponse] = []

