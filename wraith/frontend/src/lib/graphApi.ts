import { config } from './config';
import { GraphResponse } from '../types/graph';

export const fetchGraph = async (programId: string): Promise<GraphResponse> => {
  const response = await fetch(`${config.graphDbUrl}/programs/${programId}/graph`);
  if (!response.ok) {
    throw new Error('Failed to fetch graph data');
  }
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
