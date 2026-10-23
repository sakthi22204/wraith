import { NextResponse } from 'next/server';
import { describeApiError } from '@/lib/apiError';

export async function PATCH(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  // Only the advisory mode is writable here. Scope and aggressiveness have
  // their own audited routes; a general PATCH would put an accidental scope
  // widening one typo away.
  const { id } = await params;
  const adminToken = process.env.ADMIN_API_TOKEN;
  const graphDbUrl = process.env.GRAPH_DB_URL || 'http://graph_api:8001';
  const baseUrl = graphDbUrl.endsWith('/api/v1') ? graphDbUrl : `${graphDbUrl}/api/v1`;

  let engagementMode: unknown;
  try {
    ({ engagement_mode: engagementMode } = await request.json());
  } catch {
    return NextResponse.json({ error: describeApiError(400), status: 400 }, { status: 400 });
  }

  if (
    engagementMode !== 'wapt' &&
    engagementMode !== 'redteam' &&
    engagementMode !== 'both'
  ) {
    return NextResponse.json(
      { error: "engagement_mode must be 'wapt', 'redteam', or 'both'", status: 400 },
      { status: 400 }
    );
  }

  try {
    const response = await fetch(`${baseUrl}/investigations/${id}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ engagement_mode: engagementMode }),
    });

    if (!response.ok) {
      const detail = await response.text();
      console.error(
        `[api/investigations/:id] graph_db PATCH -> ${response.status}: ${detail}`
      );
      return NextResponse.json(
        { error: describeApiError(response.status), status: response.status },
        { status: response.status }
      );
    }

    return NextResponse.json(await response.json());
  } catch (error: any) {
    return NextResponse.json({ error: describeApiError(502), status: 502 }, { status: 502 });
  }
}

export async function DELETE(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  // No inbound auth token here on purpose; see the note in the killswitch route.
  // This one is destructive, so the exposure that matters is that the panel is
  // published to 127.0.0.1 only, not that it re-authenticates the browser.
  const { id } = await params;
  const adminToken = process.env.ADMIN_API_TOKEN;
  const graphDbUrl = process.env.GRAPH_DB_URL || 'http://graph_api:8001';
  const baseUrl = graphDbUrl.endsWith('/api/v1') ? graphDbUrl : `${graphDbUrl}/api/v1`;

  try {
    const response = await fetch(`${baseUrl}/investigations/${id}?confirm=true`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${adminToken}`
      }
    });

    if (!response.ok) {
      const error = await response.text();
      return NextResponse.json({ error }, { status: response.status });
    }

    const data = await response.json();
    return NextResponse.json(
      data.warning ? { status: 'success', warning: data.warning } : { status: 'success' }
    );
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
