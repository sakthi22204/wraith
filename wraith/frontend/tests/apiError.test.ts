import { ApiError, errorMessage, safeDetail, safeHostList } from '../src/lib/apiError';

describe('apiError', () => {
  describe('errorMessage', () => {
    it('uses the sanitized status description when there is no detail', () => {
      expect(errorMessage(new ApiError(502), 'fallback')).toBe('502 - upstream unavailable');
    });

    it('keeps message sanitized even when a detail is attached', () => {
      // Callers must render through errorMessage; .message never carries the
      // detail, so a stray console.log or error boundary cannot leak it.
      const err = new ApiError(400, 'evil.com');
      expect(err.message).toBe('400 - invalid request');
      expect(err.detail).toBe('evil.com');
      expect(errorMessage(err, 'Failed to start recon')).toBe('evil.com');
    });

    it('prefers an attached detail when one survived safeDetail', () => {
      const err = new ApiError(400, 'evil.com');
      expect(errorMessage(err, 'Failed to start recon')).toBe('evil.com');
    });

    it('falls back for a plain Error', () => {
      expect(errorMessage(new Error('boom'), 'Failed to start recon')).toBe('Failed to start recon');
    });

    it('falls back for a non-Error throw', () => {
      expect(errorMessage('boom', 'Failed to start recon')).toBe('Failed to start recon');
    });

    it('passes through a message that already looks sanitized', () => {
      expect(errorMessage(new Error('404 - not found'), 'fallback')).toBe('404 - not found');
    });

    it('refuses a message that merely contains the sanitized pattern', () => {
      // The pattern is anchored, so a message that only *contains* it falls
      // through to the fallback instead of promoting a path into the UI.
      expect(errorMessage(new Error('request 400 - failed at /etc/passwd'), 'fallback')).toBe('fallback');
    });
  });

  describe('safeHostList', () => {
    it('accepts bare hostname lists only', () => {
      expect(safeHostList('evil.com')).toBe('evil.com');
      expect(safeHostList('evil.com,foo.test')).toBe('evil.com,foo.test');
      expect(safeHostList(' evil.com , foo.test ')).toBe('evil.com , foo.test');
      expect(safeHostList('api.dev.crypto.com')).toBe('api.dev.crypto.com');
    });

    it('rejects injected or non-hostname values', () => {
      expect(safeHostList('evil.com\r\nX-Evil: 1')).toBeUndefined();
      expect(safeHostList('evil.com:8080')).toBeUndefined();
      expect(safeHostList('evil.com,<script>')).toBeUndefined();
      expect(safeHostList('evil.com,,foo.test')).toBeUndefined();
      expect(safeHostList('')).toBeUndefined();
      expect(safeHostList(null)).toBeUndefined();
      expect(safeHostList(undefined)).toBeUndefined();
      expect(safeHostList('a'.repeat(200))).toBeUndefined();
    });
  });

  describe('safeDetail', () => {
    it('prefers the structured header over the prose detail', () => {
      const body = {
        detail: 'Requested domains out of scope for program 8bf81dd9-1: evil.com',
      };
      expect(safeDetail(400, body, 'evil.com,foo.test')).toBe('evil.com,foo.test');
    });

    it('accepts a bare hostname list from a 400 body', () => {
      expect(safeDetail(400, { detail: 'evil.com' })).toBe('evil.com');
      expect(safeDetail(400, { detail: 'evil.com,foo.test' })).toBe('evil.com,foo.test');
      expect(safeDetail(400, { detail: 'evil.com, foo.test' })).toBe('evil.com, foo.test');
      expect(safeDetail(400, { detail: 'api.dev.crypto.com' })).toBe('api.dev.crypto.com');
    });

    it('rejects the prose sentence when no header is present', () => {
      expect(
        safeDetail(400, { detail: 'Requested domains out of scope for program 8bf81dd9-1: evil.com' })
      ).toBeUndefined();
    });

    it('ignores a header on any status other than 400', () => {
      expect(safeDetail(500, { detail: 'evil.com' }, 'evil.com')).toBeUndefined();
      expect(safeDetail(403, { detail: 'evil.com' }, 'evil.com')).toBeUndefined();
    });

    it('ignores a header that is not a bare hostname list', () => {
      expect(safeDetail(400, {}, 'evil.com\r\nX-Evil: 1')).toBeUndefined();
    });

    it('rejects prose, stack traces and paths', () => {
      expect(safeDetail(400, { detail: 'Out of scope for program 8bf81dd9: evil.com' })).toBeUndefined();
      expect(safeDetail(400, { detail: 'Traceback (most recent call last)' })).toBeUndefined();
      expect(safeDetail(400, { detail: '/etc/passwd' })).toBeUndefined();
      expect(safeDetail(400, { detail: 'http://internal-host/admin' })).toBeUndefined();
    });

    it('rejects a list element that is not a bare hostname', () => {
      expect(safeDetail(400, { detail: 'evil.com,' })).toBeUndefined();
      expect(safeDetail(400, { detail: 'evil.com, /etc/passwd' })).toBeUndefined();
    });

    it('rejects multi-line and over-long messages', () => {
      expect(safeDetail(400, { detail: 'evil.com\nfoo.test' })).toBeUndefined();
      expect(safeDetail(400, { detail: 'a'.repeat(200) })).toBeUndefined();
    });

    it('tolerates a missing or non-string detail', () => {
      expect(safeDetail(400, {})).toBeUndefined();
      expect(safeDetail(400, null)).toBeUndefined();
      expect(safeDetail(400, { detail: 42 })).toBeUndefined();
    });
  });
});
