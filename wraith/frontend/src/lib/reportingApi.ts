import { config } from './config';

export const fetchReport = async (programId: string, findingId?: string, format: 'markdown' | 'pdf' = 'markdown') => {
  const adminToken = process.env.NEXT_PUBLIC_ADMIN_API_TOKEN || 'dev-token-change-me';
  const url = findingId
    ? `${config.reportingUrl}/api/v1/reports/${programId}/findings/${findingId}?format=${format}`
    : `${config.reportingUrl}/api/v1/reports/${programId}?format=${format}`;

  const response = await fetch(url, {
    headers: {
      'Authorization': `Bearer ${adminToken}`
    }
  });
  if (!response.ok) throw new Error('Failed to fetch report');

  if (format === 'pdf') {
    return response.blob();
  }
  return response.text();
};
