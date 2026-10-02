import { config } from './config';
import { ApiError, safeDetail } from './apiError';

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

// Mutating calls go through the Next.js proxy, which attaches ADMIN_API_TOKEN.
// `POST /recon/start` spawns tool containers on the host Docker socket and is
// admin-gated upstream, so a direct call from the browser would 401.
export const startRecon = async (investigationId: string, domains: string[]) => {
  const response = await fetch('/api/recon/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ investigation_id: investigationId, domains })
  });
  // A 400 here is the orchestrator refusing domains outside the investigation's
  // authorized scope. Its `detail` is a sentence naming the program id, so the
  // rejected domains arrive in a dedicated header that we still revalidate
  // before showing; anything unexpected degrades to the sanitized status.
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const outOfScope = response.headers.get('X-Wraith-Out-Of-Scope');
    throw new ApiError(response.status, safeDetail(response.status, body, outOfScope));
  }
  return response.json();
};

export const cancelRecon = async (sessionId: string) => {
  const response = await fetch(`/api/recon/${sessionId}/cancel`, {
    method: 'POST'
  });
  if (!response.ok) throw new ApiError(response.status);
  return response.json();
};

export const fetchReconStatus = async (sessionId: string) => {
  const response = await fetch(`${config.reconUrl}/api/v1/recon/${sessionId}/status`);
  if (!response.ok) throw new ApiError(response.status);
  return response.json();
};

export const listReconSessions = async (investigationId: string): Promise<ReconSession[]> => {
  const response = await fetch(`${config.reconUrl}/api/v1/recon/sessions?investigation_id=${investigationId}`);
  if (!response.ok) throw new ApiError(response.status);
  return response.json();
};
