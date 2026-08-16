import { NextResponse } from 'next/server';

const ALLOWED_ACTIONS = ['activate', 'deactivate'] as const;
type KillswitchAction = (typeof ALLOWED_ACTIONS)[number];

function isAllowedAction(value: unknown): value is KillswitchAction {
  return (
    typeof value === 'string' &&
    (ALLOWED_ACTIONS as readonly string[]).includes(value)
  );
}

function getExploitRunnerBaseUrl(): string {
  const raw = process.env.EXPLOIT_RUNNER_URL || 'http://active_exploit_runner:8004';
  return raw.endsWith('/api/v1') ? raw : `${raw}/api/v1`;
}

export async function GET() {
  const adminToken = process.env.ADMIN_API_TOKEN;

  try {
    const response = await fetch(
      `${getExploitRunnerBaseUrl()}/killswitch/status`,
      {
        headers: adminToken ? { Authorization: `Bearer ${adminToken}` } : {},
      }
    );
    const data = await response.json().catch(() => ({}));
    return NextResponse.json(data, { status: response.status });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}

export async function POST(request: Request) {
  let action: unknown;
  try {
    const body = await request.json();
    action = body?.action;
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  if (!isAllowedAction(action)) {
    return NextResponse.json({ error: 'Unsupported killswitch action' }, { status: 400 });
  }

  const adminToken = process.env.ADMIN_API_TOKEN;

  try {
    const response = await fetch(
      `${getExploitRunnerBaseUrl()}/killswitch/${action}`,
      {
        method: 'POST',
        headers: adminToken ? { Authorization: `Bearer ${adminToken}` } : {},
      }
    );
    const data = await response.json().catch(() => ({}));
    return NextResponse.json(data, { status: response.status });
  } catch (error: any) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }
}
