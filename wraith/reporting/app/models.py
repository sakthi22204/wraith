from pydantic import BaseModel, Field, AliasChoices, computed_field
from typing import List, Optional
from datetime import datetime

class ReportFinding(BaseModel):
    title: str
    vulnerability_type: str # CWE ID + OWASP
    severity: str
    cvss_score: str
    cvss_vector: Optional[str] = None
    ai_confidence: str
    affected_asset: str
    description: str
    steps_to_reproduce: str
    exploit_poc: str
    evidence: str
    business_impact: str
    suggested_remediation: str
    discovery_metadata: dict # tool, timestamp, program

class ProgramReport(BaseModel):
    investigation_name: str = Field(..., validation_alias=AliasChoices("investigation_name", "program_name"))
    generated_at: datetime
    findings: List[ReportFinding]
    summary_line: Optional[str] = None

    @computed_field
    @property
    def program_name(self) -> str:
        return self.investigation_name
