import { config } from './config';

export const startRecon = async (programId: string, domains: string[]) => {
  const response = await fetch(`${config.reconUrl}/recon/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ program_id: programId, domains })
  });
  if (!response.ok) throw new Error('Failed to start recon');
  return response.json();
};

export const cancelRecon = async (sessionId: string) => {
  const response = await fetch(`${config.reconUrl}/recon/${sessionId}/cancel`, {
    method: 'POST'
  });
  if (!response.ok) throw new Error('Failed to cancel recon');
  return response.json();
};

export const fetchReconStatus = async (sessionId: string) => {
  const response = await fetch(`${config.reconUrl}/recon/${sessionId}/status`);
  if (!response.ok) throw new Error('Failed to fetch recon status');
  return response.json();
};
