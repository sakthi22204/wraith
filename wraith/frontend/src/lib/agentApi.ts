import { AgentStep } from '../types/graph';
import { config } from './config';
import { ApiError } from './apiError';

export type AgentEvent = {
  data: string;
  event?: string;
};

export const subscribeToAgentStream = (
  sessionId: string,
  onMessage: (data: AgentStep) => void,
  onError: (error: Event) => void,
  onEnd?: () => void,
  onOpen?: () => void
) => {
  const url = `${config.agentUrl}/api/v1/agent/sessions/${sessionId}/stream`;
  const eventSource = new EventSource(url);

  eventSource.onopen = () => {
    if (onOpen) onOpen();
  };

  eventSource.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch (e) {
      console.error('Failed to parse agent event', e);
    }
  };

  eventSource.addEventListener('end', () => {
    if (onEnd) onEnd();
    eventSource.close();
  });

  eventSource.onerror = (error) => {
    onError(error);
  };

  return () => {
    eventSource.close();
  };
};

export const fetchSessionStatus = async (sessionId: string) => {
  const response = await fetch(`${config.agentUrl}/api/v1/agent/sessions/${sessionId}/status`);
  if (!response.ok) throw new ApiError(response.status);
  return response.json();
};

export const fetchAgentSessions = async (investigationId: string) => {
  const response = await fetch(`${config.agentUrl}/api/v1/agent/sessions?investigation_id=${investigationId}`);
  if (!response.ok) throw new ApiError(response.status);
  return response.json();
};

// Mutating calls go through the Next.js proxy, which attaches ADMIN_API_TOKEN;
// `POST /sessions` is admin-gated upstream. Reads below stay direct because those
// routes are open.
export const startAgentSession = async (investigationId: string, targetScope: string[], maxIterations: number) => {
  const response = await fetch('/api/agent/sessions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ program_id: investigationId, target_scope: targetScope, max_iterations: maxIterations })
  });
  // Carry the status so the caller can show a sanitized reason instead of a
  // bare "Failed to start session"; the proxy's body may hold upstream detail.
  if (!response.ok) throw new ApiError(response.status);
  return response.json();
};

export const stopAgentSession = async (sessionId: string) => {
  const response = await fetch(`/api/agent/sessions/${sessionId}/stop`, {
    method: 'POST'
  });
  if (!response.ok) throw new ApiError(response.status);
  return response.json();
};
