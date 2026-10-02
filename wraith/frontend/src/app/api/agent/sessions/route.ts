import { NextResponse } from 'next/server';

// Proxy for exploit_agent's `POST /sessions`, which starts an agent session that
// can generate real traffic against the targets in `target_scope`. The token is
// added here because the browser cannot present a server-side secret.
export async function POST(request: Request) {
  // No inbound auth on purpose; see the note in the killswitch route.
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  // `investigation_id` is accepted alongside `program_id` because the panel uses
  // both names for the same thing.
  const payload = body as {
    program_id?: unknown;
    investigation_id?: unknown;
    target_scope?: unknown;
    max_iterations?: unknown;
  };

  const programId =
    typeof payload?.program_id === 'string' && payload.program_id
      ? payload.program_id
      : typeof payload?.investigation_id === 'string' && payload.investigation_id
        ? payload.investigation_id
        : '';

  if (
    !programId ||
    !Array.isArray(payload?.target_scope) ||
    payload.target_scope.length === 0 ||
    !payload.target_scope.every((t) => typeof t === 'string' && t.length > 0)
  ) {
    return NextResponse.json(
      { error: 'program_id and a non-empty target_scope list of strings are required' },
      { status: 400 }
    );
  }

  const maxIterations =
    typeof payload.max_iterations === 'number' && Number.isFinite(payload.max_iterations)
      ? Math.trunc(payload.max_iterations)
      : undefined;

  const adminToken = process.env.ADMIN_API_TOKEN;
  const raw = process.env.AGENT_URL || process.env.EXPLOIT_AGENT_URL || 'http://exploit_agent:8003';
  const baseUrl = raw.endsWith('/api/v1/agent') ? raw : `${raw.replace(/\/$/, '')}/api/v1/agent`;

  try {
    const response = await fetch(`${baseUrl}/sessions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        program_id: programId,
        target_scope: payload.target_scope,
        ...(maxIterations !== undefined ? { max_iterations: maxIterations } : {})
      })
    });

    const data = await response.json().catch(() => ({}));
    return NextResponse.json(data, { status: response.status });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}