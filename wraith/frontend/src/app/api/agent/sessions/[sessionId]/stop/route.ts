import { NextResponse } from 'next/server';

// Proxy for `POST /agent/sessions/{session_id}/stop`. Token added here because
// the browser cannot present a server-side secret.
export async function POST(
  _request: Request,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  const { sessionId } = await params;

  if (!/^[A-Za-z0-9_.:-]+$/.test(sessionId)) {
    return NextResponse.json({ error: 'Invalid session id' }, { status: 400 });
  }

  const adminToken = process.env.ADMIN_API_TOKEN;
  const raw = process.env.AGENT_URL || process.env.EXPLOIT_AGENT_URL || 'http://exploit_agent:8003';
  const baseUrl = raw.endsWith('/api/v1/agent') ? raw : `${raw.replace(/\/$/, '')}/api/v1/agent`;

  try {
    const response = await fetch(`${baseUrl}/sessions/${sessionId}/stop`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    const data = await response.json().catch(() => ({}));
    return NextResponse.json(data, { status: response.status });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}