import { NextResponse } from 'next/server';
import { describeApiError } from '@/lib/apiError';

/**
 * Read an investigation's assessment report.
 *
 * assessment_service's GET /assessments/{id} is admin-gated whenever the report
 * is not already cached -- it calls require_admin_token itself rather than
 * inheriting the POST route's dependency. The browser cannot present
 * ADMIN_API_TOKEN, so calling it directly from the page returned 401 on every
 * poll and the score widget could never populate. This proxy attaches the
 * token, matching the review and investigation routes.
 *
 * No inbound auth: reachable only from the browser, and the panel is published
 * to 127.0.0.1 only. See the note in the killswitch route.
 */
export async function GET(
  _request: Request,
  { params }: { params: Promise<{ investigationId: string }> }
) {
  const adminToken = process.env.ADMIN_API_TOKEN;
  const raw = process.env.ASSESSMENT_SERVICE_URL || 'http://assessment_service:8007';
  const baseUrl = raw.endsWith('/api/v1') ? raw : `${raw.replace(/\/$/, '')}/api/v1`;

  if (!adminToken) {
    console.error('[api/assessments] ADMIN_API_TOKEN is not configured on the panel');
    return NextResponse.json(
      { error: describeApiError(500), status: 500 },
      { status: 500 }
    );
  }

  const { investigationId } = await params;
  // Keep the proxy from being turned into a fetch-any-URL relay.
  if (typeof investigationId !== 'string' || !/^[A-Za-z0-9-]{1,64}$/.test(investigationId)) {
    return NextResponse.json({ error: describeApiError(400), status: 400 }, { status: 400 });
  }

  try {
    const response = await fetch(`${baseUrl}/assessments/${investigationId}`, {
      headers: { 'Authorization': `Bearer ${adminToken}` },
      cache: 'no-store',
    });

    if (!response.ok) {
      const detail = await response.text();
      console.error(
        `[api/assessments] assessment_service -> ${response.status}: ${detail}`
      );
      return NextResponse.json(
        { error: describeApiError(response.status), status: response.status },
        { status: response.status }
      );
    }

    return NextResponse.json(await response.json(), { status: 200 });
  } catch (error: any) {
    console.error(`[api/assessments] upstream unreachable: ${error?.message}`);
    return NextResponse.json({ error: describeApiError(502), status: 502 }, { status: 502 });
  }
}
