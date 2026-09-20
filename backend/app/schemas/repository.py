from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, ConfigDict

class RepositoryBase(BaseModel):
    url: str

class RepositoryCreate(RepositoryBase):
    pass

class RepositorySignalSchema(BaseModel):
    stars: int = 0
    forks: int = 0
    watchers: int = 0
    open_issues: int = 0
    recent_commits: int = 0
    commit_frequency_per_month: float = 0.0
    contributor_count: int = 0
    top_contributor_commit_ratio: float = 0.0
    latest_release_tag: Optional[str] = None
    latest_release_date: Optional[datetime] = None
    release_age_days: Optional[int] = None
    release_frequency_per_year: float = 0.0
    missing_fields: List[str] = []
    collected_at: Optional[datetime] = None

class RepositorySchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    owner: str
    name: str
    url: str
    description: Optional[str] = None
    language: Optional[str] = None
    license: Optional[str] = None
    created_at_repo: Optional[datetime] = None
    updated_at_repo: Optional[datetime] = None
    archived: bool = False
    signals: Optional[RepositorySignalSchema] = None

