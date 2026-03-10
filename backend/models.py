from sqlalchemy import Column, Integer, String, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from backend.database import Base

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="User")  # User or Admin
    messages = relationship("Message", back_populates="user")
    scans = relationship("Scan", back_populates="user")

class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    target_domain = Column(String, index=True)
    status = Column(String, default="Pending") # Pending, Running, Completed, Failed
    scan_type = Column(String) # Basic Scan, Recon Scan, Full Scan
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="scans")

class Subdomain(Base):
    __tablename__ = "subdomains"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    domain = Column(String, index=True)
    is_alive = Column(Boolean, default=False)

class Endpoint(Base):
    __tablename__ = "endpoints"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    url = Column(String)
    status_code = Column(Integer, nullable=True)
    method = Column(String, nullable=True)

class Directory(Base):
    __tablename__ = "directories"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    path = Column(String)

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"))
    severity = Column(String)
    description = Column(String)
    tool = Column(String) # e.g. nuclei

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    content = Column(String)
    user = relationship("User", back_populates="messages")
