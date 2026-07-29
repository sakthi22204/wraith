import { config } from './config';

export interface ReconSession {
  id: string;
  investigation_id: string;
  program_id?: string;
  domains: string[];
  status: 'running' | 'completed' | 'partial' | 'failed' | 'accepted';
  started_at: string;
  completed_at?: string;
  tool_results?: {
    hosts_found: number;
    ports_found: number;
    endpoints_found: number;
    tool_statuses: Record<string, string>;
  };
}

export const startRecon = async (investigationId: string, domains: string[]) => {
  const response = await fetch(`${config.reconUrl}/api/v1/recon/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ investigation_id: investigationId, domains })
  });
  if (!response.ok) throw new Error('Failed to start recon');
  return response.json();
};

export const cancelRecon = async (sessionId: string) => {
  const response = await fetch(`${config.reconUrl}/api/v1/recon/${sessionId}/cancel`, {
    method: 'POST'
  });
  if (!response.ok) throw new Error('Failed to cancel recon');
  return response.json();
};

export const fetchReconStatus = async (sessionId: string) => {
  const response = await fetch(`${config.reconUrl}/api/v1/recon/${sessionId}/status`);
  if (!response.ok) throw new Error('Failed to fetch recon status');
  return response.json();
};

export const listReconSessions = async (investigationId: string): Promise<ReconSession[]> => {
  const response = await fetch(`${config.reconUrl}/api/v1/recon/sessions?investigation_id=${investigationId}`);
  if (!response.ok) throw new Error('Failed to fetch recon sessions');
  return response.json();
};
