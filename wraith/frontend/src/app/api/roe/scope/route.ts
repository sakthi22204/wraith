import { NextResponse } from 'next/server';

export async function POST(request: Request) {
  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const adminToken = process.env.ADMIN_API_TOKEN;
  const raw = process.env.EXPLOIT_RUNNER_URL || 'http://active_exploit_runner:8004';
  const baseUrl = raw.endsWith('/api/v1') ? raw : `${raw.replace(/\/$/, '')}/api/v1`;

  const payload = body as {
    investigation_id?: unknown;
    pattern?: unknown;
    rule_type?: unknown;
    allow_aggressive?: unknown;
  };

  if (typeof payload?.investigation_id !== 'string' || !payload.investigation_id) {
    return NextResponse.json(
      { error: 'investigation_id is required' },
      { status: 400 }
    );
  }
  if (typeof payload?.pattern !== 'string' || !payload.pattern.trim()) {
    return NextResponse.json(
      { error: 'pattern is required' },
      { status: 400 }
    );
  }
  if (payload?.rule_type !== 'allow' && payload?.rule_type !== 'deny') {
    return NextResponse.json(
      { error: 'rule_type must be "allow" or "deny"' },
      { status: 400 }
    );
  }

  const allowAggressive = typeof payload?.allow_aggressive === 'boolean' ? payload.allow_aggressive : false;

  try {
    const response = await fetch(`${baseUrl}/roe/scope`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`
      },
      body: JSON.stringify({
        investigation_id: payload.investigation_id,
        pattern: payload.pattern.trim(),
        rule_type: payload.rule_type,
        allow_aggressive: allowAggressive
      })
    });

    const data = await response.json().catch(() => ({}));
    return NextResponse.json(data, { status: response.status });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
