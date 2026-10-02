import { NextResponse } from 'next/server';

// Proxy for recon_orchestrator's mutating routes. `POST /recon/start` spawns tool
// containers on the host Docker socket and `POST /recon/{id}/cancel` tears them
// down, so both now require the admin token upstream. The browser cannot present
// that token -- ADMIN_API_TOKEN is a server-side secret -- so the panel's own
// buttons have to reach these through Next.js, which adds the header here.
//
// Read routes (status, sessions) are not proxied: they are unauthenticated
// upstream and the client calls them directly.
export async function POST(request: Request) {
  // No inbound auth on purpose; see the note in the killswitch route. The control
  // that matters is that this port is published to 127.0.0.1 only.
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const adminToken = process.env.ADMIN_API_TOKEN;
  const raw = process.env.RECON_ORCHESTRATOR_URL || 'http://recon_orchestrator:8002';
  const baseUrl = raw.endsWith('/api/v1/recon') ? raw : `${raw.replace(/\/$/, '')}/api/v1/recon`;

  // The domains list is what becomes recon scope; letting the browser name an
  // arbitrary target set is the thing this gate exists to bound.
  const payload = body as { investigation_id?: unknown; domains?: unknown };
  if (
    typeof payload?.investigation_id !== 'string' ||
    !payload.investigation_id ||
    !Array.isArray(payload.domains) ||
    payload.domains.length === 0 ||
    !payload.domains.every((d) => typeof d === 'string' && d.length > 0)
  ) {
    return NextResponse.json(
      { error: 'investigation_id and a non-empty list of domain strings are required' },
      { status: 400 }
    );
  }

  try {
    const response = await fetch(`${baseUrl}/start`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        investigation_id: payload.investigation_id,
        domains: payload.domains
      })
    });

    const data = await response.json().catch(() => ({}));
    // NextResponse.json does not carry upstream headers, so the orchestrator's
    // structured list of rejected domains would be lost here. Forward exactly
    // that one header, by name -- never blanket-copy upstream headers, which
    // would let the orchestrator set cookies or CORS on the panel's origin.
    const headers: Record<string, string> = {};
    const outOfScope = response.headers.get('X-Wraith-Out-Of-Scope');
    if (outOfScope) headers['X-Wraith-Out-Of-Scope'] = outOfScope;
    return NextResponse.json(data, { status: response.status, headers });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}