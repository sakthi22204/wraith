import { config } from './config';
import { GraphResponse } from '../types/graph';

export const fetchGraph = async (programId: string): Promise<GraphResponse> => {
  const response = await fetch(`${config.graphDbUrl}/programs/${programId}/graph`);
  if (!response.ok) {
    throw new Error('Failed to fetch graph data');
  }
  return response.json();
};

export const createProgram = async (name: string, platform: string, scope_domains: string[]) => {
  const response = await fetch(`${config.graphDbUrl}/programs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, platform, scope_domains })
  });
  if (!response.ok) throw new Error('Failed to create program');
  return response.json();
};

export const deleteProgram = async (programId: string) => {
  const response = await fetch(`${config.graphDbUrl}/programs/${programId}?confirm=true`, {
    method: 'DELETE'
  });
  if (!response.ok) throw new Error('Failed to delete program');
  return response.json();
};

export const fetchFindings = async (programId: string) => {
  const response = await fetch(`${config.graphDbUrl}/programs/${programId}/findings`);
  if (!response.ok) throw new Error('Failed to fetch findings');
  return response.json();
};

export const fetchReviewQueue = async (programId: string) => {
  const response = await fetch(`${config.graphDbUrl}/programs/${programId}/findings/review-queue`);
  if (!response.ok) throw new Error('Failed to fetch review queue');
  return response.json();
};

export const reviewFinding = async (findingId: string, decision: string, note: string) => {
  const response = await fetch(`${config.graphDbUrl}/findings/${findingId}/review`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision, note })
  });
  if (!response.ok) throw new Error('Failed to review finding');
  return response.json();
};

export const fetchPrograms = async () => {
  // Although not explicitly in requirements, we'll need this for the landing page
  const response = await fetch(`${config.graphDbUrl}/programs`);
  if (!response.ok) {
     // If the endpoint doesn't exist yet, return an empty list for safety
     return [];
  }
  return response.json();
};
