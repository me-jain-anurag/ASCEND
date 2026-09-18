const BASE = 'http://127.0.0.1:8000';

/**
 * Turn a failed response into a message that says what to DO about it.
 *
 * FastAPI puts the explanation in `detail`, and the service writes those to be
 * actionable ("the API process is not in the docker group", "the lab
 * containers are not running"). Reporting only "API error 503" throws that
 * away and leaves the reader guessing — which cost real debugging time when
 * /api/verify alone failed while every other endpoint was fine.
 */
async function describe(res: Response, path: string): Promise<string> {
  let detail = '';
  try {
    const body = await res.json();
    detail = typeof body?.detail === 'string' ? body.detail : '';
  } catch {
    /* non-JSON error body — fall back to the status line */
  }
  return detail
    ? `${path} failed (${res.status}): ${detail}`
    : `${path} failed (${res.status} ${res.statusText || 'error'})`;
}

export const api = {
  async get<T>(path: string): Promise<T> {
    const res = await fetch(`${BASE}${path}`);
    if (!res.ok) throw new Error(await describe(res, path));
    return res.json();
  },
  async post<T>(path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${BASE}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
    });
    if (!res.ok) throw new Error(await describe(res, path));
    return res.json();
  },
};
