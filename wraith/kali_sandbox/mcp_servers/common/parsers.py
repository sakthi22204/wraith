from pydantic import BaseModel
from typing import List, Optional, Any

class NmapPort(BaseModel):
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None

class NmapResult(BaseModel):
    target: str
    ports: List[NmapPort]
    raw_output: Optional[str] = None

class NucleiFinding(BaseModel):
    template_id: str
    info: dict
    type: str
    host: str
    matched_at: str
    severity: str

class NucleiResult(BaseModel):
    findings: List[NucleiFinding]
    raw_output: Optional[str] = None

class SQLMapResult(BaseModel):
    target: str
    vulnerable: bool
    vulns: List[dict] = []
    raw_output: Optional[str] = None

class HydraResult(BaseModel):
    target: str
    service: str
    valid_credentials: List[dict] = []
    raw_output: Optional[str] = None

class MetasploitModule(BaseModel):
    fullname: str
    name: str
    type: str
    rank: str
    description: Optional[str] = None

class MetasploitResult(BaseModel):
    module: str
    success: bool
    session_info: Optional[dict] = None
    raw_output: Optional[str] = None
