export interface Node {
  id: string;
  labels: string[];
  properties: Record<string, any>;
}

export interface Link {
  source: string;
  target: string;
  type: string;
}

export interface GraphResponse {
  nodes: Node[];
  links: Link[];
}

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface Program {
  id: string;
  name: string;
  platform: string;
  scope_domains: string[];
  created_at: string;
  target?: string;
}

export interface Finding {
  id: string;
  vuln_type: string;
  severity: Severity;
  confidence: string;
  status: string;
  description: string;
  discovered_at: string;
  ai_confidence?: number | null;
  ai_reasoning?: string;
  corroborating_sources?: string[];
  cvss_vector?: string;
  evidence?: string;
}

export interface ExploitProposal {
  id: number;
  program_id: string;
  investigation_id?: string;
  target: string;
  action: string;
  params: Record<string, any>;
  status: string;
  created_at: string;
}

export interface AgentStep {
  reason?: {
    reasoning_log: string[];
    next_tool?: string;
    next_tool_params?: Record<string, any>;
  };
  call_tool?: {
    reasoning_log: string[];
    last_tool_result: string;
  };
  record_finding?: {
    findings_this_session: Finding[];
  };
  propose_exploit?: {
    reasoning_log: string[];
  };
  [key: string]: any;
}

export interface ReconSession {
  id: string;
  status: string;
  progress: number;
}

export interface AgentSession {
  id: string;
  status: string;
}
