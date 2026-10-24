/**
 * Same-origin JSON client.
 *
 * Every request rides the session cookie and echoes the double-submit CSRF
 * cookie in `x-csrf-token`. It never throws: an unreachable relay comes back as
 * `status: 0` carrying {@link NETWORK_ERROR}, so callers handle one shape.
 *
 * The method follows the body: no body is a GET. A `POST` that takes no body
 * must therefore pass `{}`, or it will be sent — and refused — as a GET.
 */

export const NETWORK_ERROR = 'We could not reach the server. Check your connection and try again.';

const CSRF_COOKIE = '__Host-weaver_csrf';

export interface ApiResult<T> {
	ok: boolean;
	status: number;
	data: T | null;
	/** The relay's `{ error }` message, or the network error. */
	error: string | null;
	/** The input a refusal is scoped to, when the relay names one. */
	field: string | null;
}

function csrfToken(): string | null {
	const match = new RegExp(`(?:^|; )${CSRF_COOKIE}=([^;]*)`).exec(document.cookie);
	return match ? decodeURIComponent(match[1]) : null;
}

export async function api<T = unknown>(path: string, body?: unknown): Promise<ApiResult<T>> {
	const headers: Record<string, string> = { accept: 'application/json' };
	const csrf = csrfToken();
	if (csrf) {
		headers['x-csrf-token'] = csrf;
	}
	if (body !== undefined) {
		headers['content-type'] = 'application/json';
	}

	let response: Response;
	let data: (T & { error?: string; field?: string }) | null;
	try {
		response = await fetch(path, {
			method: body === undefined ? 'GET' : 'POST',
			credentials: 'same-origin',
			headers,
			body: body === undefined ? undefined : JSON.stringify(body)
		});
		const text = await response.text();
		data = text ? (JSON.parse(text) as T & { error?: string; field?: string }) : null;
	} catch {
		return { ok: false, status: 0, data: null, error: NETWORK_ERROR, field: null };
	}

	return {
		ok: response.ok,
		status: response.status,
		data,
		error: data?.error ?? null,
		field: data?.field ?? null
	};
}
