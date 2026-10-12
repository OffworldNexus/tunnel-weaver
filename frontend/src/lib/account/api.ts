/**
 * Same-origin JSON client.
 *
 * Every request is sent with `credentials: 'same-origin'` so the session and
 * CSRF cookies ride along, and never leaves the relay origin.
 */

export interface ApiResult<T> {
	ok: boolean;
	status: number;
	data: T | null;
}

export interface ApiOptions {
	method?: string;
	body?: unknown;
	csrf?: string | null;
}

export async function api<T = unknown>(
	path: string,
	options: ApiOptions = {}
): Promise<ApiResult<T>> {
	const headers: Record<string, string> = { accept: 'application/json' };
	const init: RequestInit = {
		method: options.method ?? 'GET',
		credentials: 'same-origin',
		headers
	};

	if (options.body !== undefined) {
		headers['content-type'] = 'application/json';
		init.body = JSON.stringify(options.body);
	}
	if (options.csrf) {
		headers['x-csrf-token'] = options.csrf;
	}

	const response = await fetch(path, init);
	const text = await response.text();
	let data: T | null = null;
	if (text) {
		try {
			data = JSON.parse(text) as T;
		} catch {
			data = null;
		}
	}

	return { ok: response.ok, status: response.status, data };
}

/** Extracts the server's `{ error }` message, falling back to a generic one. */
export function messageOf(data: unknown, fallback: string): string {
	if (data && typeof data === 'object' && 'error' in data) {
		const value = (data as Record<string, unknown>).error;
		if (typeof value === 'string' && value.trim().length > 0) {
			return value;
		}
	}
	return fallback;
}

/**
 * Extracts the `field` a refusal belongs to, when the relay scoped it to one
 * input (WVR-50), so a form can place the message on that field. `null` means
 * the refusal is form-wide.
 */
export function fieldOf(data: unknown): string | null {
	if (data && typeof data === 'object' && 'field' in data) {
		const value = (data as Record<string, unknown>).field;
		if (typeof value === 'string' && value.trim().length > 0) {
			return value;
		}
	}
	return null;
}
