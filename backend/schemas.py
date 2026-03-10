from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: int
    email: EmailStr
    role: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class ScanCreate(BaseModel):
    target_domain: str
    scan_type: str

class ScanResponse(BaseModel):
    id: int
    target_domain: str
    status: str
    scan_type: str
    created_at: datetime
    
    # Optionally include relations
    # subdomains: list
    # vulnerabilities: list
    
    class Config:
        from_attributes = True
