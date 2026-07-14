import { config } from './config';

export interface ReconSession {
  id: string;
  program_id: string;
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

export const startRecon = async (programId: string, domains: string[]) => {
  const response = await fetch(`${config.reconUrl}/api/v1/recon/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ program_id: programId, domains })
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

export const listReconSessions = async (programId: string): Promise<ReconSession[]> => {
  const response = await fetch(`${config.reconUrl}/api/v1/recon/sessions?program_id=${programId}`);
  if (!response.ok) throw new Error('Failed to fetch recon sessions');
  return response.json();
};
