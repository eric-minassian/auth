/** Thin fetch wrapper for the same-origin `/api/*` surface. */

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers: body === undefined ? {} : { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  // Guard JSON.parse: a 502/timeout often returns an HTML body, which would
  // otherwise throw an opaque SyntaxError that masks the real status code.
  let data: unknown;
  try {
    data = text ? (JSON.parse(text) as unknown) : undefined;
  } catch {
    if (!response.ok) {
      throw new ApiError(response.status, "error", response.statusText || "Request failed");
    }
    throw new ApiError(response.status, "invalid_response", "Unexpected server response");
  }
  if (!response.ok) {
    const err = data as { error?: string; message?: string } | undefined;
    throw new ApiError(
      response.status,
      err?.error ?? "error",
      err?.message ?? response.statusText,
    );
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};

export interface SessionInfo {
  user: { user_id: string; nickname: string };
  session: { created_at: number; amr: string[] };
}

export interface RecoveryReadiness {
  passkey_count: number;
  recovery_codes_remaining: number;
}

export interface PasskeyInfo {
  credential_id: string;
  name: string;
  created_at: number;
  last_used_at: number | null;
  /** Backup-eligible (syncable passkey) hint; `null`/absent if unknown. */
  backup_eligible?: boolean | null;
  /** Backup-state (currently backed up) hint. */
  backup_state?: boolean | null;
}

export interface SessionListItem {
  session_id: string;
  created_at: number;
  last_seen_at: number;
  amr: string[];
  current: boolean;
  /** Coarse "Browser on OS" device label captured at sign-in. */
  device?: string | null;
  /** Coarse region (ISO country code) captured at sign-in. */
  region?: string | null;
}
