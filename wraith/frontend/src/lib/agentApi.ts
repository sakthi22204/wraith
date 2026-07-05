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
  const url = `${config.agentUrl}/agent/sessions/${sessionId}/stream`;
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
