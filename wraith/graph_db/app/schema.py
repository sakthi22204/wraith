from pydantic import BaseModel, Field, AliasChoices, computed_field
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum

class FindingStatus(str, Enum):
    UNCONFIRMED = "UNCONFIRMED"
    AI_VALIDATED = "AI_VALIDATED"
    CORROBORATED = "CORROBORATED"
    HUMAN_CONFIRMED = "HUMAN_CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DUPLICATE = "DUPLICATE"

    @classmethod
    def _missing_(cls, value: object):
        if not isinstance(value, str):            return None
        # Handle legacy "confirmed" or "unconfirmed" lowercase values
        val_upper = value.upper()
        if val_upper == "CONFIRMED":
            return cls.HUMAN_CONFIRMED
        for member in cls:
            if member.value == val_upper:
                return member
        return None

# Base Models
class ProgramBase(BaseModel):
    name: str
    platform: str
    scope_domains: List[str] = []

class ProgramCreate(ProgramBase):
    pass

class Program(ProgramBase):
    id: str
    created_at: datetime

# Investigation Models (New Primary Entity)
class InvestigationBase(BaseModel):
    name: str
    target: str
    platform: Optional[str] = "automatic"

class InvestigationCreate(InvestigationBase):
    pass

class Investigation(InvestigationBase):
    id: str
    scope_domains: List[str] = []
    created_at: datetime

    @computed_field
    @property
    def program_id(self) -> str:
        return self.id

class HostBase(BaseModel):
    value: str

class HostCreate(HostBase):
    pass

class Host(HostBase):
    id: str
    first_seen: datetime
    last_seen: datetime

class PortBase(BaseModel):
    number: int
    protocol: str # tcp/udp
    state: str
    source_tool: Optional[str] = None

class PortCreate(PortBase):
    pass

class Port(PortBase):
    id: str

class ServiceBase(BaseModel):
    name: str
    version: Optional[str] = None
    banner: Optional[str] = None

class ServiceCreate(ServiceBase):
    pass

class Service(ServiceBase):
    id: str

class EndpointBase(BaseModel):
    url: str
    method: str
    source_tool: Optional[str] = None

class EndpointCreate(EndpointBase):
    pass

class Endpoint(EndpointBase):
    id: str
    first_seen: datetime

class ParameterBase(BaseModel):
    name: str
    location: str # query/body/header/cookie
    param_type: str

class ParameterCreate(ParameterBase):
    pass

class Parameter(ParameterBase):
    id: str

class FindingBase(BaseModel):
    # A human-readable headline. Reports previously had to synthesise one by
    # slicing the description, which produced titles like "INFO DISCLOSURE in
    # Scanner reported a /metrics endpoint ex..." in every finding.
    title: Optional[str] = None
    vuln_type: str
    severity: str
    confidence: str
    status: FindingStatus
    description: str
    ai_confidence: Optional[float] = None
    ai_reasoning: Optional[str] = None
    corroborating_sources: Optional[List[str]] = None
    cvss_vector: Optional[str] = None
    evidence: Optional[str] = None

    # --- Validation evidence -------------------------------------------
    # Populated only by an executed validation. ai_confidence alone must never
    # be sufficient to populate these; see require_validation_evidence().
    poc_request: Optional[str] = None
    poc_response: Optional[str] = None
    expected_result: Optional[str] = None
    actual_result: Optional[str] = None
    steps_to_reproduce: Optional[str] = None
    root_cause: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None
    validation_stage: str = "NOT_VALIDATED"


class ValidationAttemptBase(BaseModel):
    """One executed validation exchange, stored verbatim as evidence."""
    request: Dict[str, Any] = Field(default_factory=dict)
    response: Dict[str, Any] = Field(default_factory=dict)
    expected_result: str = ""
    actual_result: str = ""
    outcome: str = "INCONCLUSIVE"
    stage_achieved: str = "NOT_VALIDATED"
    scope_decision: str = ""
    rate_limit_decision: str = ""
    killswitch_decision: str = ""
    elapsed_ms: Optional[float] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ValidationAttemptCreate(ValidationAttemptBase):
    finding_id: Optional[str] = None


class ValidationAttempt(ValidationAttemptBase):
    id: str


#: Fields that must all be present before a finding may claim a validated
#: status. Deliberately excludes ai_confidence: a model being sure of itself is
#: not evidence.
REQUIRED_VALIDATION_FIELDS = (
    "poc_request",
    "poc_response",
    "expected_result",
    "actual_result",
    "validation_stage",
)

#: Statuses that assert the finding is real. Reaching one of these without the
#: evidence above is rejected.
VALIDATED_STATUSES = frozenset({
    FindingStatus.AI_VALIDATED.value,
    FindingStatus.CORROBORATED.value,
    FindingStatus.HUMAN_CONFIRMED.value,
})


def require_validation_evidence(data: dict) -> Optional[str]:
    """Return an error message if `data` claims validation without evidence.

    This is the enforcement point for "AI confidence must never validate".
    It lives in the schema so every write path inherits it: a direct API call,
    the agent's graph client, and any future caller all get the same answer.
    """
    status = data.get("status")
    if not isinstance(status, str):
        status = getattr(status, "value", None)
    if status not in VALIDATED_STATUSES:
        return None

    missing = [f for f in REQUIRED_VALIDATION_FIELDS if not str(data.get(f) or "").strip()]
    if missing:
        return (
            f"status '{status}' requires executed validation evidence; missing: "
            f"{', '.join(missing)}. AI confidence alone cannot validate a finding."
        )
    return None


class FindingCreate(FindingBase):
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    target_id: str
    target_type: str


class Finding(FindingBase):
    id: str
    discovered_at: datetime
    # Denormalized link back to the affected asset. Stored on the node by
    # create_finding; without it here pydantic drops it and the reporting
    # service cannot resolve which endpoint/parameter a finding belongs to.
    target_id: Optional[str] = None
    target_type: Optional[str] = None


class FindingUpdate(BaseModel):
    """Partial update used to attach executed evidence to a finding.

    Every field is optional, but ``status`` is still subject to
    ``require_validation_evidence``: the gate is applied against the merged
    result of the existing node and this patch, so a partial write cannot
    launder a finding into a validated state.
    """
    title: Optional[str] = None
    status: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    evidence: Optional[str] = None
    poc_request: Optional[str] = None
    poc_response: Optional[str] = None
    expected_result: Optional[str] = None
    actual_result: Optional[str] = None
    validation_stage: Optional[str] = None
    steps_to_reproduce: Optional[str] = None
    root_cause: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None

class FalsePositivePatternBase(BaseModel):
    vuln_type: str
    endpoint_pattern: str
    parameter_name: Optional[str] = None
    reason: str

class FalsePositivePatternCreate(FalsePositivePatternBase):
    pass

class FalsePositivePattern(FalsePositivePatternBase):
    id: str
    created_at: datetime

class CVEBase(BaseModel):
    cve_id: str
    cvss_score: float
    description: str

class CVECreate(CVEBase):
    pass

class CVE(CVEBase):
    id: str

class ToolBase(BaseModel):
    name: str
    version: str

class ToolCreate(ToolBase):
    pass

class Tool(ToolBase):
    id: str

class ScanSessionBase(BaseModel):
    started_at: datetime
    status: str

class ScanSessionCreate(ScanSessionBase):
    pass

class ScanSession(ScanSessionBase):
    id: str
    ended_at: Optional[datetime] = None

class ReconSessionBase(BaseModel):
    investigation_id: str = Field(..., validation_alias=AliasChoices("investigation_id", "program_id"))
    domains: List[str]
    status: str # "running"|"completed"|"partial"|"failed"
    started_at: datetime = Field(default_factory=datetime.utcnow)

class ReconSessionCreate(ReconSessionBase):
    pass

class ReconSession(ReconSessionBase):
    id: str
    completed_at: Optional[datetime] = None
    tool_results: Optional[dict] = None # JSON summary of counts

    @computed_field
    @property
    def program_id(self) -> str:
        return self.investigation_id

class AgentSessionBase(BaseModel):
    investigation_id: str = Field(..., validation_alias=AliasChoices("investigation_id", "program_id"))
    status: str # "running"|"completed"|"failed"|"paused_rate_limited"|"stopped"|"interrupted"
    started_at: datetime = Field(default_factory=datetime.utcnow)
    iteration_count: int = 0
    tools_used: List[str] = []
    reasoning_log: List[str] = []

class AgentSessionCreate(AgentSessionBase):
    pass

class AgentSession(AgentSessionBase):
    id: str
    completed_at: Optional[datetime] = None
    final_report: Optional[str] = None

    @computed_field
    @property
    def program_id(self) -> str:
        return self.investigation_id

# For the Graph GET endpoint
class Node(BaseModel):
    id: str
    labels: List[str]
    properties: dict

class Link(BaseModel):
    source: str
    target: str
    type: str

class GraphResponse(BaseModel):
    nodes: List[Node]
    links: List[Link]
