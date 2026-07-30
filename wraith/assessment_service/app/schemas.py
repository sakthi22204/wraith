from pydantic import BaseModel
from typing import List, Dict, Optional, Any
from datetime import datetime

class TargetPriority(BaseModel):
    target_id: str
    host: str
    type: str # Endpoint / Parameter / Host
    risk_score: float
    reason: str

class CVECorrelation(BaseModel):
    cve_id: str
    title: str
    cvss_score: float
    affected_service: str

class ValidationTask(BaseModel):
    step: int
    target: str
    action: str
    reason: str

class AssessmentReport(BaseModel):
    investigation_id: str
    risk_score: float
    technologies: List[str]
    hosts_count: int
    services_count: int
    endpoints_count: int
    findings_summary: Dict[str, int] # Critical, High, Medium, Low
    prioritized_targets: List[TargetPriority]
    correlated_cves: List[CVECorrelation]
    validation_plan: List[ValidationTask]
    generated_at: datetime
