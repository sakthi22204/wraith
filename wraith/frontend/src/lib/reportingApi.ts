export const fetchReport = async (investigationId: string, findingId?: string, format: 'markdown' | 'pdf' = 'markdown') => {
  const url = findingId
    ? `/api/reports?investigationId=${investigationId}&findingId=${findingId}&format=${format}`
    : `/api/reports?investigationId=${investigationId}&format=${format}`;

  const response = await fetch(url);
  if (!response.ok) throw new Error('Failed to fetch report');

  if (format === 'pdf') {
    return response.blob();
  }
  return response.text();
};
