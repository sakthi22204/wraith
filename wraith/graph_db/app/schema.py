from pydantic import BaseModel, Field
from datetime import datetime
from typing import List, Optional

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
    vuln_type: str
    severity: str
    confidence: str
    status: str
    description: str

class FindingCreate(FindingBase):
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    target_id: str
    target_type: str

class Finding(FindingBase):
    id: str
    discovered_at: datetime

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
