import { POST } from '../src/app/api/investigations/route';
import '@testing-library/jest-dom';

const GRAPH_DB_URL = 'http://graph_api:8001';
const ADMIN_TOKEN = 'super-secret-admin-token';

const post = (body: unknown) =>
  new Request('http://localhost:3000/api/investigations', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

describe('POST /api/investigations proxy', () => {
  let fetchMock: jest.Mock;
  const originalEnv = { ...process.env };

  beforeEach(() => {
    fetchMock = jest.fn();
    global.fetch = fetchMock as any;
    process.env.ADMIN_API_TOKEN = ADMIN_TOKEN;
    process.env.GRAPH_DB_URL = GRAPH_DB_URL;
  });

  afterEach(() => {
    jest.restoreAllMocks();
    process.env = { ...originalEnv };
  });

  it('attaches the admin bearer token to the upstream graph_db request', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ id: 'inv-1' }),
    });

    await POST(post({ name: 'Test', target: 'example.com' }));

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(`${GRAPH_DB_URL}/api/v1/investigations`);
    expect(init.method).toBe('POST');
    expect(init.headers.Authorization).toBe(`Bearer ${ADMIN_TOKEN}`);
    expect(JSON.parse(init.body)).toEqual({ name: 'Test', target: 'example.com' });
  });

  it('never returns the admin token to the browser', async () => {
    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ id: 'inv-1' }),
    });

    const res = await POST(post({ name: 'Test', target: 'example.com' }));
    const body = await res.text();

    expect(body).not.toContain(ADMIN_TOKEN);
  });

  it('does not hit graph_db when the admin token is unconfigured', async () => {
    delete process.env.ADMIN_API_TOKEN;
    jest.spyOn(console, 'error').mockImplementation(() => {});

    const res = await POST(post({ name: 'Test', target: 'example.com' }));

    expect(res.status).toBe(500);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a payload with no name before contacting graph_db', async () => {
    const res = await POST(post({ target: 'example.com' }));

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'name is required' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects a payload with no target before contacting graph_db', async () => {
    const res = await POST(post({ name: 'Test' }));

    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: 'target is required' });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('logs the raw upstream detail but returns only a safe summary', async () => {
    const secretish =
      'Traceback: /app/graph_db/app/api/routes.py at host graph_api.internal:8001';
    fetchMock.mockResolvedValue({
      ok: false,
      status: 500,
      text: async () => secretish,
    });
    const logged = jest.spyOn(console, 'error').mockImplementation(() => {});

    const res = await POST(post({ name: 'Test', target: 'example.com' }));
    const body = await res.text();

    expect(res.status).toBe(500);
    // the operator keeps the diagnostic
    expect(logged).toHaveBeenCalledWith(expect.stringContaining(secretish));
    // the browser does not
    expect(body).not.toContain(secretish);
    expect(body).not.toContain('graph_api.internal');
    expect(JSON.parse(body)).toEqual({ error: '500 - server error', status: 500 });
  });

  it('surfaces an upstream 401 as a safe message instead of leaking it', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 401,
      text: async () => 'invalid admin token abcdef',
    });
    jest.spyOn(console, 'error').mockImplementation(() => {});

    const res = await POST(post({ name: 'Test', target: 'example.com' }));

    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: '401 - not authorized', status: 401 });
  });

  it('returns 502 when graph_db is unreachable', async () => {
    fetchMock.mockRejectedValue(new Error('ECONNREFUSED 10.0.0.5:8001'));
    jest.spyOn(console, 'error').mockImplementation(() => {});

    const res = await POST(post({ name: 'Test', target: 'example.com' }));

    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({
      error: '502 - upstream unavailable',
      status: 502,
    });
  });
});
