import { startRecon } from '../src/lib/reconApi';
import { ApiError, errorMessage } from '../src/lib/apiError';

describe('reconApi start failures', () => {
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn();
    global.fetch = fetchMock as any;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  const startErr = async (): Promise<ApiError> => {
    try {
      await startRecon('inv-1', ['evil.com']);
      throw new Error('expected startRecon to reject');
    } catch (e) {
      return e as ApiError;
    }
  };

  it('posts the investigation and domains to the panel proxy', async () => {
    fetchMock.mockResolvedValue({ ok: true, status: 202, json: async () => ({ session_id: 's1' }) });

    await startRecon('inv-1', ['developer.crypto.com']);

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('/api/recon/start');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body)).toEqual({
      investigation_id: 'inv-1',
      domains: ['developer.crypto.com'],
    });
  });

  it('surfaces the rejected domains from the structured header on a scope 400', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 400,
      headers: { get: (h: string) => (h === 'X-Wraith-Out-Of-Scope' ? 'evil.com,foo.test' : null) },
      json: async () => ({
        detail: 'Requested domains out of scope for program 8bf81dd9-c6eb: evil.com, foo.test',
      }),
    });

    const err = await startErr();
    expect(err.status).toBe(400);
    expect(errorMessage(err, 'Failed to start recon')).toBe('evil.com,foo.test');
  });

  it('ignores a header carrying injected content', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 400,
      headers: { get: () => 'evil.com\r\nX-Evil: 1' },
      json: async () => ({ detail: 'Requested domains out of scope for program x: evil.com' }),
    });

    const err = await startErr();
    expect(err.detail).toBeUndefined();
    expect(errorMessage(err, 'Failed to start recon')).toBe('400 - invalid request');
  });

  it('accepts a bare hostname list body when no header is sent', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 400,
      headers: { get: () => null },
      json: async () => ({ detail: 'evil.com' }),
    });

    const err = await startErr();
    expect(errorMessage(err, 'Failed to start recon')).toBe('evil.com');
  });

  it('does not surface the upstream body for a 5xx', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 502,
      headers: { get: () => 'evil.com' },
      json: async () => ({ detail: 'evil.com' }),
    });

    const err = await startErr();
    expect(errorMessage(err, 'Failed to start recon')).toBe('502 - upstream unavailable');
  });

  it('never leaks a stack trace or path from the body', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 400,
      headers: { get: () => null },
      json: async () => ({ detail: 'Traceback (most recent call last): /app/orchestrator.py:556' }),
    });

    const err = await startErr();
    expect(err.detail).toBeUndefined();
    expect(errorMessage(err, 'Failed to start recon')).toBe('400 - invalid request');
  });

  it('still reports a sanitized error when the body is not JSON', async () => {
    fetchMock.mockResolvedValue({
      ok: false,
      status: 400,
      headers: { get: () => null },
      json: async () => {
        throw new Error('Unexpected token <');
      },
    });

    const err = await startErr();
    expect(errorMessage(err, 'Failed to start recon')).toBe('400 - invalid request');
  });
});
