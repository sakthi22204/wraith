import { NextResponse } from 'next/server';

/**
 * Record a human review decision on a finding.
 *
 * This route exists because `graphApi.reviewFinding` used to POST straight to
 * graph_db from the browser. graph_db's review route is now token-guarded, so
 * that call would 401 -- and more to the point, a browser cannot present
 * ADMIN_API_TOKEN, which is deliberately a server-side secret. Attaching it here
 * is the same pattern the investigation-delete route already uses.
 *
 * No inbound auth: this path is reachable only from the browser, and the panel
 * is published to 127.0.0.1 only. See the note in the killswitch route.
 */
export async function POST(
  request: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const adminToken = process.env.ADMIN_API_TOKEN;
  const graphDbUrl = process.env.GRAPH_DB_URL || 'http://graph_api:8001';
  const baseUrl = graphDbUrl.endsWith('/api/v1') ? graphDbUrl : `${graphDbUrl}/api/v1`;

  if (!adminToken) {
    return NextResponse.json(
      { error: 'ADMIN_API_TOKEN is not configured on the panel' },
      { status: 500 }
    );
  }

  let decision: unknown;
  let note: unknown;
  try {
    ({ decision, note } = await request.json());
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  // A review may only refute. Confirmation comes from executed evidence or
  // corroboration, never from a sign-off, so 'confirmed' is rejected here too
  // rather than being forwarded to a graph_db route that would refuse it anyway.
  if (decision !== 'false_positive') {
    return NextResponse.json(
      { error: 'decision must be false_positive; there is no human confirmation path' },
      { status: 400 }
    );
  }
  if (note !== undefined && note !== null && typeof note !== 'string') {
    return NextResponse.json({ error: 'note must be a string' }, { status: 400 });
  }

  try {
    const response = await fetch(`${baseUrl}/findings/${id}/review`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`,
      },
      body: JSON.stringify({ decision, note: note ?? null }),
    });

    if (!response.ok) {
      const error = await response.text();
      return NextResponse.json({ error }, { status: response.status });
    }

    return NextResponse.json(await response.json());
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}