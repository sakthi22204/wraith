import { NextResponse } from 'next/server';
import { describeApiError } from '@/lib/apiError';

/**
 * Create an investigation.
 *
 * graph_db's POST /investigations is token-guarded, and a browser cannot
 * present ADMIN_API_TOKEN because it is a server-side secret. The proxy
 * attaches it, matching the review and investigation-delete routes.
 *
 * No inbound auth: reachable only from the browser, and the panel is published
 * to 127.0.0.1 only. See the note in the killswitch route.
 */
export async function POST(request: Request) {
  const adminToken = process.env.ADMIN_API_TOKEN;
  const graphDbUrl = process.env.GRAPH_DB_URL || 'http://graph_api:8001';
  const baseUrl = graphDbUrl.endsWith('/api/v1') ? graphDbUrl : `${graphDbUrl}/api/v1`;

  if (!adminToken) {
    console.error('[api/investigations] ADMIN_API_TOKEN is not configured on the panel');
    return NextResponse.json(
      { error: describeApiError(500), status: 500 },
      { status: 500 }
    );
  }

  let name: unknown;
  let target: unknown;
  let platform: unknown;
  let engagementMode: unknown;
  try {
    ({ name, target, platform, engagement_mode: engagementMode } = await request.json());
  } catch {
    return NextResponse.json({ error: describeApiError(400), status: 400 }, { status: 400 });
  }

  // Mirrors graph_db's InvestigationBase so a bad payload is rejected here
  // with a useful message instead of passed through.
  if (typeof name !== 'string' || !name.trim()) {
    return NextResponse.json(
      { error: 'name is required', status: 400 },
      { status: 400 }
    );
  }
  if (typeof target !== 'string' || !target.trim()) {
    return NextResponse.json(
      { error: 'target is required', status: 400 },
      { status: 400 }
    );
  }
  if (platform !== undefined && platform !== null && typeof platform !== 'string') {
    return NextResponse.json(
      { error: 'platform must be a string', status: 400 },
      { status: 400 }
    );
  }
  if (
    engagementMode !== undefined &&
    engagementMode !== null &&
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
    const response = await fetch(`${baseUrl}/investigations`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`,
      },
      body: JSON.stringify({
        name: name.trim(),
        target: target.trim(),
        ...(typeof platform === 'string' && platform.trim()
          ? { platform: platform.trim() }
          : {}),
        ...(typeof engagementMode === 'string' && engagementMode
          ? { engagement_mode: engagementMode }
          : {}),
      }),
    });

    if (!response.ok) {
      const detail = await response.text();
      console.error(
        `[api/investigations] graph_db POST /investigations -> ${response.status}: ${detail}`
      );
      return NextResponse.json(
        { error: describeApiError(response.status), status: response.status },
        { status: response.status }
      );
    }

    return NextResponse.json(await response.json(), { status: 201 });
  } catch (error: any) {
    console.error(`[api/investigations] upstream unreachable: ${error?.message}`);
    return NextResponse.json({ error: describeApiError(502), status: 502 }, { status: 502 });
  }
}
