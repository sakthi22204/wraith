import { ApiError } from './apiError';

export const fetchReport = async (investigationId: string, findingId?: string, format: 'markdown' | 'pdf' | 'html' | 'json' = 'markdown') => {
  const url = findingId
    ? `/api/reports?investigationId=${investigationId}&findingId=${findingId}&format=${format}`
    : `/api/reports?investigationId=${investigationId}&format=${format}`;

  const response = await fetch(url);
  if (!response.ok) throw new ApiError(response.status);

  if (format === 'pdf') {
    return response.blob();
  }
  return response.text();
};
