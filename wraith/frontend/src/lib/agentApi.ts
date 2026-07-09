import { config } from './config';

export type AgentEvent = {
  data: string;
  event?: string;
};

export const subscribeToAgentStream = (
  sessionId: string,
  onMessage: (data: any) => void,
  onError: (error: any) => void,
  onEnd?: () => void
) => {
  const url = `${config.agentUrl}/api/v1/agent/sessions/${sessionId}/stream`;
  const eventSource = new EventSource(url);

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
  if (!response.ok) throw new Error('Failed to fetch session status');
  return response.json();
};

export const startAgentSession = async (programId: string, targetScope: string[], maxIterations: number) => {
  const response = await fetch(`${config.agentUrl}/api/v1/agent/sessions`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ program_id: programId, target_scope: targetScope, max_iterations: maxIterations })
  });
  if (!response.ok) throw new Error('Failed to start session');
  return response.json();
};

export const stopAgentSession = async (sessionId: string) => {
  const response = await fetch(`${config.agentUrl}/api/v1/agent/sessions/${sessionId}/stop`, {
    method: 'POST'
  });
  if (!response.ok) throw new Error('Failed to stop session');
  return response.json();
};
