import { NextResponse } from 'next/server';

// Proxy for `POST /recon/{session_id}/cancel`, which stops tool containers. The
// token is added here for the reason described in ../start/route.ts.
export async function POST(
  request: Request,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  const { sessionId } = await params;

  // A session id is an opaque token the orchestrator issued; path traversal in it
  // would let the browser reach a different route on the same service.
  if (!/^[A-Za-z0-9_.:-]+$/.test(sessionId)) {
    return NextResponse.json({ error: 'Invalid session id' }, { status: 400 });
  }

  const adminToken = process.env.ADMIN_API_TOKEN;
  const raw = process.env.RECON_ORCHESTRATOR_URL || 'http://recon_orchestrator:8002';
  const baseUrl = raw.endsWith('/api/v1/recon') ? raw : `${raw.replace(/\/$/, '')}/api/v1/recon`;

  try {
    const response = await fetch(`${baseUrl}/${sessionId}/cancel`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${adminToken}` }
    });
    const data = await response.json().catch(() => ({}));
    return NextResponse.json(data, { status: response.status });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}