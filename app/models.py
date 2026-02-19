from datetime import datetime
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship
from .database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="tester")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(120), nullable=False)
    target_url = Column(String(500), nullable=False)
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    owner = relationship("User", back_populates="projects")
    hits = relationship("Hit", back_populates="project", cascade="all, delete-orphan")


class Hit(Base):
    __tablename__ = "hits"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    ip_address = Column(String(100), nullable=False)
    user_agent = Column(String(1000), default="")
    referer = Column(String(1000), default="")
    full_url = Column(String(2000), default="")
    custom_tag = Column(String(120), default="")
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False, index=True)

    project = relationship("Project", back_populates="hits")
