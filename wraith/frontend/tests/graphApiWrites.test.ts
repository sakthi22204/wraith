import { createInvestigation, deleteProgram, reviewFinding } from '../src/lib/graphApi';
import { config } from '../src/lib/config';
import { ApiError } from '../src/lib/apiError';
import '@testing-library/jest-dom';

describe('graphApi write paths', () => {
  let fetchMock: jest.Mock;

  beforeEach(() => {
    fetchMock = jest.fn();
    global.fetch = fetchMock as any;
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('createInvestigation', () => {
    it('posts to the panel proxy, never straight to graph_db', async () => {
      fetchMock.mockResolvedValue({ ok: true, status: 201, json: async () => ({ id: 'inv-1' }) });

      await createInvestigation('Test', 'example.com');

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe('/api/investigations');
      expect(url).not.toContain(config.graphDbUrl);
      expect(url).not.toContain('graph_db');
      expect(init.method).toBe('POST');
      expect(JSON.parse(init.body)).toEqual({ name: 'Test', target: 'example.com' });
    });

    it('never puts the admin token in the browser request', async () => {
      process.env.ADMIN_API_TOKEN = 'super-secret-admin-token';
      fetchMock.mockResolvedValue({ ok: true, status: 201, json: async () => ({ id: 'inv-1' }) });

      await createInvestigation('Test', 'example.com');

      const [, init] = fetchMock.mock.calls[0];
      const headers = JSON.stringify(init.headers);
      expect(headers).not.toContain('super-secret-admin-token');
      expect(headers).not.toContain('Authorization');
      delete process.env.ADMIN_API_TOKEN;
    });

    it('raises a sanitized ApiError on failure', async () => {
      fetchMock.mockResolvedValue({ ok: false, status: 500, json: async () => ({}) });

      await expect(createInvestigation('Test', 'example.com')).rejects.toThrow(ApiError);
      await expect(createInvestigation('Test', 'example.com')).rejects.toThrow('500 - server error');
    });
  });

  describe('deleteProgram', () => {
    it('deletes through the panel proxy path', async () => {
      fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => ({ deleted: true }) });

      await deleteProgram('inv-1');

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe('/api/investigations/inv-1');
      expect(init.method).toBe('DELETE');
    });

    it('raises a sanitized ApiError so the toast can name the status', async () => {
      fetchMock.mockResolvedValue({ ok: false, status: 404, json: async () => ({}) });

      await expect(deleteProgram('missing')).rejects.toThrow('404 - not found');
    });
  });

  describe('reviewFinding', () => {
    it('posts through the panel proxy path', async () => {
      fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => ({ updated: true }) });

      await reviewFinding('f-1', 'confirm', 'looks real');

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toBe('/api/findings/f-1/review');
      expect(init.method).toBe('POST');
      expect(url).not.toContain(config.graphDbUrl);
    });
  });
});
