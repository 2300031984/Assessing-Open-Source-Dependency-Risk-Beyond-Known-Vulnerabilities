from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from backend.app.database.base import Base

class Repository(Base):
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True, index=True)
    owner = Column(String(255), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    url = Column(String(512), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    language = Column(String(100), nullable=True)
    license = Column(String(100), nullable=True)
    created_at_repo = Column(DateTime, nullable=True)
    updated_at_repo = Column(DateTime, nullable=True)
    archived = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    signals = relationship("RepositorySignal", back_populates="repository", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="repository", cascade="all, delete-orphan")
    assessments = relationship("RiskAssessment", back_populates="repository", cascade="all, delete-orphan")


class RepositorySignal(Base):
    __tablename__ = "repository_signals"

    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    stars = Column(Integer, default=0)
    forks = Column(Integer, default=0)
    watchers = Column(Integer, default=0)
    open_issues = Column(Integer, default=0)
    recent_commits = Column(Integer, default=0)
    commit_frequency_per_month = Column(Float, default=0.0)
    contributor_count = Column(Integer, default=0)
    top_contributor_commit_ratio = Column(Float, default=0.0)
    latest_release_tag = Column(String(100), nullable=True)
    latest_release_date = Column(DateTime, nullable=True)
    release_age_days = Column(Integer, nullable=True)
    release_frequency_per_year = Column(Float, default=0.0)
    missing_fields_json = Column(JSON, nullable=True)
    collected_at = Column(DateTime, default=datetime.utcnow)
    source = Column(String(50), default="github")

    repository = relationship("Repository", back_populates="signals")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    vuln_id = Column(String(100), nullable=False, index=True) # OSV / CVE ID
    severity = Column(String(50), nullable=True)
    cvss_score = Column(Float, nullable=True)
    summary = Column(Text, nullable=True)
    affected_versions = Column(Text, nullable=True)
    fixed_versions = Column(Text, nullable=True)
    published_date = Column(DateTime, nullable=True)
    modified_date = Column(DateTime, nullable=True)
    source = Column(String(100), default="OSV")
    collected_at = Column(DateTime, default=datetime.utcnow)

    repository = relationship("Repository", back_populates="vulnerabilities")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(String(100), unique=True, nullable=False, index=True)
    repository_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    composite_score = Column(Float, nullable=False)
    risk_level = Column(String(20), nullable=False) # LOW, MODERATE, HIGH, CRITICAL
    explanation_summary = Column(Text, nullable=False)
    scoring_version = Column(String(20), nullable=False, default="v0.1")
    feature_version = Column(String(20), nullable=False, default="v0.1")
    is_demo_fixture = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    repository = relationship("Repository", back_populates="assessments")
    features = relationship("RiskFeature", back_populates="assessment", cascade="all, delete-orphan")


class RiskFeature(Base):
    __tablename__ = "risk_features"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(Integer, ForeignKey("risk_assessments.id"), nullable=False)
    factor_name = Column(String(100), nullable=False)
    raw_value = Column(Float, nullable=False)
    normalized_value = Column(Float, nullable=False)
    weight = Column(Float, nullable=False)
    weighted_contribution = Column(Float, nullable=False)

    assessment = relationship("RiskAssessment", back_populates="features")


class RiskConfiguration(Base):
    __tablename__ = "risk_configurations"

    id = Column(Integer, primary_key=True, index=True)
    version = Column(String(20), unique=True, nullable=False)
    weights_json = Column(JSON, nullable=False)
    thresholds_json = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
