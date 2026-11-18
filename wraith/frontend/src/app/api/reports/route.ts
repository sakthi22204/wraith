import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const investigationId = searchParams.get('investigationId') || searchParams.get('programId');
  const findingId = searchParams.get('findingId');
  const format = searchParams.get('format') || 'markdown';
  const profile = searchParams.get('profile') || 'final';

  const adminToken = process.env.ADMIN_API_TOKEN;
  const reportingUrlRaw = process.env.REPORTING_URL || 'http://reporting:8006';
  const reportingUrl = reportingUrlRaw.endsWith('/api/v1') ? reportingUrlRaw : `${reportingUrlRaw}/api/v1`;

  if (!investigationId) {
    return NextResponse.json({ error: 'Missing investigationId' }, { status: 400 });
  }

  const params = new URLSearchParams({ format });
  if (!findingId) {
    params.set('profile', profile);
  }
  const url = findingId
    ? `${reportingUrl}/reports/${investigationId}/findings/${findingId}?${params.toString()}`
    : `${reportingUrl}/reports/${investigationId}?${params.toString()}`;

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
    let contentType = 'text/markdown';
    if (format === 'html') {
      contentType = 'text/html';
    } else if (format === 'json') {
      contentType = 'application/json';
    }

    return new Response(text, {
      headers: {
        'Content-Type': contentType
      }
    });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
