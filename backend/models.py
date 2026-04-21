from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime, JSON, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.database import Base


def utcnow():
    return datetime.utcnow()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="User")  # User or Admin
    subscription_tier = Column(String, default="Free") # Free or Premium
    messages = relationship("Message", back_populates="user")
    scans = relationship("Scan", back_populates="user")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    target_domain = Column(String, index=True)
    status = Column(String, default="Pending")
    scan_type = Column(String)
    output_dir = Column(String, nullable=True)
    report_path = Column(String, nullable=True)
    graph_data = Column(JSON, default=dict)
    summary = Column(JSON, default=dict)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    monitoring_target_id = Column(Integer, ForeignKey("monitoring_targets.id"), nullable=True)
    user = relationship("User", back_populates="scans")
    monitoring_target = relationship("MonitoringTarget", back_populates="scans")
    subdomains = relationship("Subdomain", back_populates="scan", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    directories = relationship("Directory", back_populates="scan", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")
    secrets = relationship("SecretFinding", back_populates="scan", cascade="all, delete-orphan")
    graphql_findings = relationship("GraphQLFinding", back_populates="scan", cascade="all, delete-orphan")

class Target(Base):
    __tablename__ = "targets"
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True)
    project_name = Column(String, default="Default")
    last_scan = Column(DateTime, nullable=True)
    total_subdomains = Column(Integer, default=0)
    total_endpoints = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    risk_score = Column(Integer, default=0)
    last_change_detected = Column(DateTime, nullable=True)

class ScheduledJob(Base):
    __tablename__ = "scheduled_jobs"
    id = Column(Integer, primary_key=True, index=True)
    target_id = Column(Integer, ForeignKey("targets.id"))
    schedule_interval = Column(String, default="weekly") # daily, weekly, monthly
    is_active = Column(Boolean, default=True)
    next_run = Column(DateTime, nullable=True)

class Subdomain(Base):
    __tablename__ = "subdomains"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    domain = Column(String, index=True)
    is_alive = Column(Boolean, default=False)
    is_new = Column(Boolean, default=True)

class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    url = Column(String)
    host = Column(String, nullable=True)
    path = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)
    method = Column(String, nullable=True)
    is_new = Column(Boolean, default=True)

class Directory(Base):
    __tablename__ = "directories"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    path = Column(String)
    url = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)
    source = Column(String, default="ffuf")
    scan = relationship("Scan", back_populates="directories")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    severity = Column(String)
    description = Column(String)
    tool = Column(String) # e.g. nuclei
    confidence = Column(String, default="Unknown")
    exposure_level = Column(String, default="Unknown")
    priority = Column(String, default="Low")
    manual_review_required = Column(Boolean, default=False)
    is_new = Column(Boolean, default=True)

class Technology(Base):
    __tablename__ = "technologies"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    name = Column(String)
    category = Column(String, nullable=True)
    version = Column(String, nullable=True)

class GraphQL(Base):
    __tablename__ = "graphql_endpoints"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    endpoint = Column(String)
    has_introspection = Column(Boolean, default=False)

class JavaScript(Base):
    __tablename__ = "javascript_files"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    url = Column(String)
    extracted_endpoints = Column(String, nullable=True) # JSON dumped list
    extracted_parameters = Column(String, nullable=True) # JSON dumped list

class Secret(Base):
    __tablename__ = "secrets"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    value = Column(String)
    extracted_from = Column(String)
    secret_type = Column(String)
    is_new = Column(Boolean, default=True)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    content = Column(String)
    user = relationship("User", back_populates="messages")
