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

export interface Finding {
  id: string;
  vuln_type: string;
  severity: Severity;
  confidence: string;
  status: string;
  description: string;
  discovered_at: string;
}
