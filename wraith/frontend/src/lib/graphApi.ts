import { config } from './config';
import { GraphResponse } from '../types/graph';
import { ApiError } from './apiError';

const fail = async (response: Response): Promise<never> => {
  throw new ApiError(response.status);
};

export const fetchGraph = async (investigationId: string): Promise<GraphResponse> => {
  const response = await fetch(`${config.graphDbUrl}/api/v1/investigations/${investigationId}/graph`);
  if (!response.ok) return fail(response);
  return response.json();
};

export const createInvestigation = async (name: string, target: string) => {
  // Goes through the panel's own route, not graph_db directly. graph_db's
  // create route is token-guarded, and the browser cannot present
  // ADMIN_API_TOKEN -- it is a server-side secret. The panel attaches it.
  const response = await fetch('/api/investigations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, target })
  });
  if (!response.ok) return fail(response);
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
  if (!response.ok) return fail(response);
  return response.json();
};

export const fetchFindings = async (investigationId: string) => {
  const response = await fetch(`${config.graphDbUrl}/api/v1/investigations/${investigationId}/findings`);
  if (!response.ok) return fail(response);
  return response.json();
};

export const fetchReviewQueue = async (investigationId: string) => {
  const response = await fetch(`${config.graphDbUrl}/api/v1/investigations/${investigationId}/findings/review-queue`);
  if (!response.ok) return fail(response);
  return response.json();
};

export const reviewFinding = async (findingId: string, decision: string, note: string) => {
  // Goes through the panel's own route, not graph_db directly. graph_db's
  // review endpoint is token-guarded, and the browser cannot present
  // ADMIN_API_TOKEN -- it is a server-side secret. The panel attaches it.
  const response = await fetch(`/api/findings/${findingId}/review`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ decision, note })
  });
  if (!response.ok) return fail(response);
  return response.json();
};

export const fetchPrograms = async () => {
  const response = await fetch(`${config.graphDbUrl}/api/v1/investigations`);
  if (!response.ok) {
     return [];
  }
  return response.json();
};
