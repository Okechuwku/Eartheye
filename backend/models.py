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
    role = Column(String, default="Free")
    subscription_plan = Column(String, default="Free user")
    subscription_status = Column(String, default="active")
    messages = relationship("Message", back_populates="user", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")
    monitoring_targets = relationship("MonitoringTarget", back_populates="user", cascade="all, delete-orphan")

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

class Subdomain(Base):
    __tablename__ = "subdomains"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    domain = Column(String, index=True)
    is_alive = Column(Boolean, default=False)
    source = Column(String, default="subfinder")
    title = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    technologies = Column(JSON, default=list)
    scan = relationship("Scan", back_populates="subdomains")

class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    url = Column(String)
    host = Column(String, nullable=True)
    path = Column(String, nullable=True)
    status_code = Column(Integer, nullable=True)
    method = Column(String, nullable=True)
    source = Column(String, default="crawler")
    content_type = Column(String, nullable=True)
    discovered_from = Column(String, nullable=True)
    technologies = Column(JSON, default=list)
    hidden_parameters = Column(JSON, default=list)
    is_graphql = Column(Boolean, default=False)
    scan = relationship("Scan", back_populates="endpoints")

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
    tool = Column(String)
    template_id = Column(String, nullable=True)
    host = Column(String, nullable=True)
    matched_at = Column(String, nullable=True)
    evidence = Column(Text, nullable=True)
    raw_data = Column(JSON, default=dict)
    scan = relationship("Scan", back_populates="vulnerabilities")


class SecretFinding(Base):
    __tablename__ = "secret_findings"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    category = Column(String)
    severity = Column(String, default="high")
    location = Column(String)
    source_url = Column(String, nullable=True)
    value_preview = Column(String, nullable=True)
    confidence = Column(String, default="medium")
    raw_match = Column(Text, nullable=True)
    scan = relationship("Scan", back_populates="secrets")


class GraphQLFinding(Base):
    __tablename__ = "graphql_findings"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    endpoint = Column(String)
    introspection_enabled = Column(Boolean, default=False)
    schema_types = Column(Integer, nullable=True)
    notes = Column(Text, nullable=True)
    source = Column(String, default="graphql")
    scan = relationship("Scan", back_populates="graphql_findings")


class MonitoringTarget(Base):
    __tablename__ = "monitoring_targets"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    domain = Column(String, index=True)
    scan_type = Column(String, default="Recon Scan")
    interval_minutes = Column(Integer, default=720)
    enabled = Column(Boolean, default=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    last_snapshot = Column(JSON, default=dict)
    last_diff = Column(JSON, default=dict)
    created_at = Column(DateTime, default=utcnow)
    user = relationship("User", back_populates="monitoring_targets")
    scans = relationship("Scan", back_populates="monitoring_target")

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    content = Column(String)
    user = relationship("User", back_populates="messages")
