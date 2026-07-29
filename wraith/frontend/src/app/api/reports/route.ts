import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const investigationId = searchParams.get('investigationId') || searchParams.get('programId');
  const findingId = searchParams.get('findingId');
  const format = searchParams.get('format') || 'markdown';

  const adminToken = process.env.ADMIN_API_TOKEN;
  const reportingUrl = process.env.REPORTING_URL || 'http://reporting:8006';

  if (!investigationId) {
    return NextResponse.json({ error: 'Missing investigationId' }, { status: 400 });
  }

  const url = findingId
    ? `${reportingUrl}/api/v1/reports/${investigationId}/findings/${findingId}?format=${format}`
    : `${reportingUrl}/api/v1/reports/${investigationId}?format=${format}`;

  try {
    const response = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${adminToken}`
      }
    });

    if (!response.ok) {
      const error = await response.text();
      return NextResponse.json({ error }, { status: response.status });
    }

    if (format === 'pdf') {
      const blob = await response.blob();
      return new Response(blob, {
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': response.headers.get('Content-Disposition') || 'attachment; filename=report.pdf'
        }
      });
    }

    const text = await response.text();
    return new Response(text, {
      headers: {
        'Content-Type': 'text/markdown'
      }
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
