from pydantic import BaseModel, Field, AliasChoices, computed_field
from typing import List, Optional
from datetime import datetime

class ReportFinding(BaseModel):
    title: str
    vulnerability_type: str # CWE ID + OWASP
    severity: str
    cvss_score: str
    cvss_vector: Optional[str] = None
    # True when the vector is a class/access-level baseline inferred at report
    # time rather than a finding-specific vector recorded during validation.
    cvss_provisional: bool = False
    ai_confidence: str
    affected_asset: str
    affected_endpoints: List[str] = Field(default_factory=list)
    screenshots: List[dict] = Field(default_factory=list)
    description: str
    steps_to_reproduce: str
    exploit_poc: str
    evidence: str
    business_impact: str
    suggested_remediation: str
    poc_request: Optional[str] = None
    poc_response: Optional[str] = None
    expected_result: Optional[str] = None
    actual_result: Optional[str] = None
    validation_stage: Optional[str] = None
    # CONFIRMED or UNVALIDATED. Set by the generator from the graph status and
    # the presence of a real request/response exchange, so a consumer never has
    # to re-derive it and cannot accidentally treat a hypothesis as a finding.
    validation_state: Optional[str] = None
    # A confirmed finding is not automatically a submittable one: the captured
    # request/response and the expected/actual pair are what let a triager
    # replay it. ``evidence_gaps`` names what is missing.
    submittable: bool = False
    evidence_gaps: List[str] = Field(default_factory=list)
    discovery_metadata: dict # tool, timestamp, program
    risk_rating: Optional[dict] = None
    timeline: Optional[list] = []
    attack_graph: Optional[dict] = None
    support_resources: Optional[list] = []

class ProgramReport(BaseModel):
    investigation_name: str = Field(..., validation_alias=AliasChoices("investigation_name", "program_name"))
    generated_at: datetime
    findings: List[ReportFinding]
    summary_line: Optional[str] = None
    executive_summary: Optional[dict] = None
    timeline: Optional[list] = []
    attack_graph: Optional[dict] = None
    support_resources: Optional[list] = []
    # What the assessment was able to look at. Optional because the assessment
    # service may be unreachable; a report renders without it.
    coverage: Optional[dict] = None
    # Selected from the investigation's engagement_mode or an explicit request.
    report_profile: Optional[str] = None
    submission_guidance: Optional[dict] = None
    # Confirmed findings whose evidence is incomplete. They stay in the report
    # marked unsubmittable rather than disappearing; a missing capture is an
    # evidence problem, not a reason to hide a confirmed issue.
    evidence_warnings: List[dict] = Field(default_factory=list)
    # Probes that a human triager would reject as non-findings (for example an
    # OPTIONS response, or a 404 page that merely echoes the requested path).
    # They are retained here so the final report can explain the exclusion
    # instead of silently inflating the confirmed count.
    excluded_non_findings: List[dict] = Field(default_factory=list)

    @computed_field
    @property
    def program_name(self) -> str:
        return self.investigation_name
