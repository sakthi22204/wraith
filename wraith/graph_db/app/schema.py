from pydantic import BaseModel, Field, AliasChoices, computed_field
from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from enum import Enum

# Which advisory skill set an investigation runs under. This is deliberately
# separate from `aggressive`: it selects methodology context and the report
# profile, and never widens scope or relaxes a runner gate.
EngagementMode = Literal["wapt", "redteam", "both"]

class FindingStatus(str, Enum):
    UNCONFIRMED = "UNCONFIRMED"
    #: A negative signal was observed -- a missing control (rate limit not
    #: enforced, a security header absent) -- but no vulnerability was
    #: exercised. Distinct from UNCONFIRMED, which is a positive signal seen
    #: but not yet validated. Mixing the two loses which of the two states a
    #: finding is actually in.
    OBSERVATION = "OBSERVATION"
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
    # Explicit authorization for active traffic (aggressive recon scanners and
    # exploit payload tools) against the investigation's hosts. Defaults True:
    # an investigation exists to be tested, so the operator opts out rather than
    # in. It is the authoritative record the runner's scope rules are seeded
    # from; the runner refuses aggressive tools unless the covering rule said so.
    aggressive: bool = True

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
    aggressive: bool = True
    # `wapt` loads application-assessment methodology; `redteam` adds perimeter
    # and identity skills; `both` is the union. Older records have no property
    # and read as the default here, so no migration is required.
    engagement_mode: EngagementMode = "wapt"

class InvestigationCreate(InvestigationBase):
    pass

class InvestigationUpdate(BaseModel):
    engagement_mode: Optional[EngagementMode] = None

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
    # The principal the proof was obtained as: "unauthenticated", or the label
    # of the identity used. Severity is judged differently for a bug anyone can
    # reach than one that needed a session, and the poc_request alone does not
    # reliably say which it was, so the fact is recorded rather than inferred.
    probe_principal: Optional[str] = None
    # Three-source confirmation. The independent sources that back this finding:
    # "agent_probe" (P, a criterion the AI agent authored), "exploitation"
    # (E, an executed exploit) and "mcp_tool_result" (M, a sandbox scanner's
    # result; "mcp_tool_result_named" when it explicitly named this vuln_type).
    # Stored rather than recomputed so the derived status is queryable and the
    # provenance is auditable. A validated status asserted on a source set that
    # cannot support it is refused; see enforce_evidence_sources().
    evidence_sources: Optional[List[str]] = None


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


#: The independent sources of evidence a finding can rest on.
EVIDENCE_AGENT_PROBE = "agent_probe"
EVIDENCE_EXPLOITATION = "exploitation"
EVIDENCE_MCP_TOOL = "mcp_tool_result"
EVIDENCE_MCP_TOOL_NAMED = "mcp_tool_result_named"


def _sources_support_validation(evidence_sources) -> bool:
    """Whether a set of sources is enough to call a finding validated.

    A single source is never enough: an agent's claim (P) is not proof, and a
    scanner hit (M) is a guess the target happened to answer. Two independent
    sources are required -- an agent probe (P) with an executed exploit (E) or a
    tool result (M), or an exploit (E) with a tool that explicitly named the
    issue (M-named). The last case is the only one where M alone can complete
    the pair, because a scanner that says "SQL injection here" has identified
    the vulnerability rather than merely flagged the endpoint.
    """
    s = set(evidence_sources or [])
    if EVIDENCE_AGENT_PROBE in s and (
        EVIDENCE_EXPLOITATION in s or EVIDENCE_MCP_TOOL in s
    ):
        return True
    return EVIDENCE_EXPLOITATION in s and EVIDENCE_MCP_TOOL_NAMED in s


def enforce_evidence_sources(merged: dict) -> Optional[str]:
    """Correct a validated status that its source set cannot support.

    Returns the status the finding should carry instead, or ``None`` when the
    patch is fine. Only *downgrades* -- a source set can revoke a validation
    claim but can never grant one, so a verdict the runner already declined
    (e.g. a differential bug proven only by reachability) is never re-promoted
    here.

    A patch that carries no ``evidence_sources`` is left alone: callers that do
    not participate in the three-source model keep their existing behaviour.
    """
    sources = merged.get("evidence_sources")
    if sources is None:
        return None

    status = merged.get("status")
    if not isinstance(status, str):
        status = getattr(status, "value", None)
    if status not in VALIDATED_STATUSES:
        return None
    if _sources_support_validation(sources):
        return None
    return FindingStatus.UNCONFIRMED.value


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
    # Typed as the enum, not ``str``: the write path used to accept any string
    # and hand it straight to Neo4j, so a single PATCH could store a status the
    # read model's enum has no member for -- every later GET then raised a
    # ValidationError (500) instead of returning the finding. Coercing here
    # rejects an unknown status at the boundary (422) rather than poisoning the
    # node.
    status: Optional[FindingStatus] = None
    severity: Optional[str] = None
    # A label, not a score -- same as FindingBase. This was declared float while
    # the base was str, so a create stored "0.8" and an update to the same node
    # stored 0.8: one Neo4j property holding two types, with nothing to say
    # which. Producers genuinely send both forms ("high", "certain", "0.8"), and
    # nothing ever compares this field numerically -- the review queue orders on
    # ai_confidence -- so it is carried through to reports as a display label.
    # Numeric scoring lives in ai_confidence, which is a float.
    confidence: Optional[str] = None
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
    probe_principal: Optional[str] = None
    evidence_sources: Optional[List[str]] = None

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
    # The resolved mode is copied onto the session so a report can say what
    # context produced it even if the investigation is re-moded later. Old
    # sessions have no property and read as None.
    engagement_mode: Optional[EngagementMode] = None

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
