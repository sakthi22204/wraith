import { config } from './config';

export const fetchReport = async (programId: string, findingId?: string, format: 'markdown' | 'pdf' = 'markdown') => {
  const url = findingId
    ? `${config.reportingUrl}/reports/${programId}/findings/${findingId}?format=${format}`
    : `${config.reportingUrl}/reports/${programId}?format=${format}`;

  const response = await fetch(url);
  if (!response.ok) throw new Error('Failed to fetch report');

  if (format === 'pdf') {
    return response.blob();
  }
  return response.text();
};
