import { ApiError } from './apiError';

export const fetchReport = async (
  investigationId: string,
  findingId?: string,
  format: 'markdown' | 'pdf' | 'html' | 'json' = 'markdown',
  profile: 'auto' | 'bugcrowd' | 'hackerone' | 'redteam' | 'final' = 'final',
) => {
  const params = new URLSearchParams({ investigationId, format });
  if (findingId) {
    params.set('findingId', findingId);
  } else {
    params.set('profile', profile);
  }
  const url = `/api/reports?${params.toString()}`;

  const response = await fetch(url);
  if (!response.ok) throw new ApiError(response.status);

  if (format === 'pdf') {
    return response.blob();
  }
  return response.text();
};
