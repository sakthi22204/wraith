export type ApiErrorBody = {
  error: string;
  status?: number;
};

const REASONS: Record<number, string> = {
  400: 'invalid request',
  401: 'not authorized',
  403: 'forbidden',
  404: 'not found',
  405: 'method not allowed',
  409: 'conflict',
  422: 'invalid request',
  500: 'server error',
  502: 'upstream unavailable',
  503: 'service unavailable',
  504: 'upstream timeout',
};

/**
 * Renders a user-safe message for an upstream status. Deliberately built only
 * from the status code: backend bodies can carry stack traces, internal
 * hostnames and file paths, so they are logged server-side and never returned.
 */
export const describeApiError = (status: number): string => {
  const reason = REASONS[status] ?? (status >= 500 ? 'server error' : 'request failed');
  return `${status} - ${reason}`;
};

// Each comma-separated element must be a bare hostname on its own. Prose,
// stack traces, paths and URLs all contain punctuation or whitespace and so
// fail this, degrading to the sanitized status instead.
const HOST_RE = /^[\w.-]+$/;
const MAX_DETAIL_LENGTH = 120;

export class ApiError extends Error {
  readonly status: number;
  readonly detail?: string;

  constructor(status: number, detail?: string) {
    super(describeApiError(status));
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Returns the value only if it is a comma-separated list of bare hostnames.
 * Used to vet the orchestrator's scope-rejection header before it is shown; the
 * header is built from raw client input server-side, so it is revalidated here
 * rather than trusted.
 */
export const safeHostList = (value: string | null | undefined): string | undefined => {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > MAX_DETAIL_LENGTH) return undefined;
  const parts = trimmed.split(',').map(part => part.trim());
  if (parts.some(part => !HOST_RE.test(part))) return undefined;
  return trimmed;
};

/**
 * Accepts an upstream message only when it is a comma-separated list of bare
 * hostnames. Messages carrying anything else are rejected so they can only
 * degrade to the sanitized status.
 *
 * `outOfScope` is the orchestrator's structured header and is preferred when
 * present, since the `detail` sentence names the program id and cannot pass
 * this check by design.
 *
 * Note the message field itself stays sanitized even when a detail is
 * attached; callers must render through `errorMessage` to see it.
 */
export const safeDetail = (
  status: number,
  body: unknown,
  outOfScope?: string | null
): string | undefined => {
  if (status !== 400) return undefined;
  const fromHeader = safeHostList(outOfScope);
  if (fromHeader) return fromHeader;
  const detail = (body as { detail?: unknown } | null)?.detail;
  if (typeof detail !== 'string') return undefined;
  return safeHostList(detail);
};

export const errorMessage = (error: unknown, fallback: string): string => {
  if (error instanceof ApiError) return error.detail ?? error.message;
  if (error instanceof Error && /^\d{3} - /.test(error.message)) return error.message;
  return fallback;
};
