import { config } from './config';
import { GraphResponse } from '../types/graph';

export const fetchGraph = async (investigationId: string): Promise<GraphResponse> => {
  const response = await fetch(`${config.graphDbUrl}/api/v1/investigations/${investigationId}/graph`);
  if (!response.ok) {
    throw new Error('Failed to fetch graph data');
  }
  return response.json();
};

export const createInvestigation = async (name: string, target: string) => {
  const response = await fetch(`${config.graphDbUrl}/api/v1/investigations`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, target })
  });
  if (!response.ok) throw new Error('Failed to create investigation');
  return response.json();
};

export const createProgram = async (name: string, platform: string, scope_domains: string[]) => {
  // Legacy support
  return createInvestigation(name, scope_domains[0] || "unknown");
};

export const deleteProgram = async (investigationId: string) => {
  const response = await fetch(`/api/investigations/${investigationId}`, {
    method: 'DELETE',
  });
  if (!response.ok) throw new Error('Failed to delete investigation');
  return response.json();
};

export const fetchFindings = async (investigationId: string) => {
  const response = await fetch(`${config.graphDbUrl}/api/v1/investigations/${investigationId}/findings`);
  if (!response.ok) throw new Error('Failed to fetch findings');
  return response.json();
};

export const fetchReviewQueue = async (investigationId: string) => {
  const response = await fetch(`${config.graphDbUrl}/api/v1/investigations/${investigationId}/findings/review-queue`);
  if (!response.ok) throw new Error('Failed to fetch review queue');
  return response.json();
};

export const reviewFinding = async (findingId: string, decision: string, note: string) => {
  const response = await fetch(`${config.graphDbUrl}/api/v1/findings/${findingId}/review`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision, note })
  });
  if (!response.ok) throw new Error('Failed to review finding');
  return response.json();
};

export const fetchPrograms = async () => {
  const response = await fetch(`${config.graphDbUrl}/api/v1/investigations`);
  if (!response.ok) {
     return [];
  }
  return response.json();
};
