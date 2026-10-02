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

class AssessmentCoverage(BaseModel):
    """What the assessment was actually able to look at.

    A risk score with nothing under it is ambiguous: 2.0 means the same thing
    on a target whose API was never reached and on one where every route was
    found, probed and found safe. These counters let the two be told apart,
    which is the difference between "no vulnerabilities" and "no evidence".
    """
    # Did discovery reach the application at all?
    endpoints_discovered: int = 0
    javascript_bundles: int = 0
    api_endpoints: int = 0
    # Were those endpoints turned into things to actually try? Note there is
    # deliberately no "candidates generated" counter: candidate hypotheses are
    # not persisted to the graph, so any such number would be invented here
    # rather than measured. These are counted from what was written.
    findings_recorded: int = 0
    candidate_families: List[str] = []
    validations_run: int = 0
    validations_inconclusive: int = 0
    findings_confirmed: int = 0
    # Why coverage may be incomplete, in plain words.
    gaps: List[str] = []


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
    coverage: AssessmentCoverage
