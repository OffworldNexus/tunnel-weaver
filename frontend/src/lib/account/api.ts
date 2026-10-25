/**
 * Same-origin JSON client.
 *
 * Every request rides the session cookie and echoes the double-submit CSRF
 * cookie in `x-csrf-token`. It never throws: an unreachable relay comes back as
 * `status: 0` carrying {@link NETWORK_ERROR}, so callers handle one shape.
 *
 * A request the relay refuses for want of authentication (a `401` or `403`
 * carrying `x-weaver-required-level`) is handed to the caller's
 * {@link RefusalHandler} with the level that would have been enough and the
 * ways to reach it. A write must pass one — the type checker refuses a write
 * call without it — because a write is an action the person asked for, and
 * whoever offers the action has to decide what a refusal means for it. Nothing
 * is retried: once the handler has taken the person up, it re-issues the call
 * itself if it wants to.
 */
import type { AuthLevel, UpgradePath } from '#lib/app/session.svelte';

export const NETWORK_ERROR = 'We could not reach the server. Check your connection and try again.';

const CSRF_COOKIE = '__Host-weaver_csrf';

const REQUIRED_LEVEL_HEADER = 'x-weaver-required-level';
const UPGRADE_PATHS_HEADER = 'x-weaver-upgrade-paths';

export type WriteMethod = 'POST' | 'PUT' | 'PATCH' | 'DELETE';
export type Method = 'GET' | WriteMethod;

/**
 * What to do when the session is too weak for a call: `requiredLevel` is what
 * the route needs, `upgradePaths` the ways there (each an ordered list of
 * steps), the preferred first.
 *
 * The wrapper awaits the handler and ignores what it gives back, so a handler
 * that reports whether it got there — `climb` does — passes as-is.
 */
export type RefusalHandler = (
	requiredLevel: AuthLevel,
	upgradePaths: UpgradePath[]
) => void | Promise<unknown>;

export interface ApiResult<T> {
	ok: boolean;
	status: number;
	data: T | null;
	/** The relay's `{ error }` message, or the network error. */
	error: string | null;
	/** The input a refusal is scoped to, when the relay names one. */
	field: string | null;
	/** Whether this was an authentication refusal (and the handler has run). */
	refused: boolean;
}

function csrfToken(): string | null {
	const match = new RegExp(`(?:^|; )${CSRF_COOKIE}=([^;]*)`).exec(document.cookie);
	return match ? decodeURIComponent(match[1]) : null;
}

/** The ways up a refusal names; an unreadable header reads as none. */
function upgradePaths(response: Response): UpgradePath[] {
	try {
		const parsed: unknown = JSON.parse(response.headers.get(UPGRADE_PATHS_HEADER) ?? '[]');
		return Array.isArray(parsed) ? (parsed as UpgradePath[]) : [];
	} catch {
		return [];
	}
}

export function api<T = unknown>(
	method: 'GET',
	path: string,
	data?: undefined,
	onRefusal?: RefusalHandler
): Promise<ApiResult<T>>;
export function api<T = unknown>(
	method: WriteMethod,
	path: string,
	data: unknown,
	onRefusal: RefusalHandler
): Promise<ApiResult<T>>;
export async function api<T = unknown>(
	method: Method,
	path: string,
	data?: unknown,
	onRefusal?: RefusalHandler
): Promise<ApiResult<T>> {
	const headers: Record<string, string> = { accept: 'application/json' };
	const csrf = csrfToken();
	if (csrf) {
		headers['x-csrf-token'] = csrf;
	}
	if (data !== undefined) {
		headers['content-type'] = 'application/json';
	}

	let response: Response;
	let body: (T & { error?: string; field?: string }) | null;
	try {
		response = await fetch(path, {
			method,
			credentials: 'same-origin',
			headers,
			body: data === undefined ? undefined : JSON.stringify(data)
		});
		const text = await response.text();
		body = text ? (JSON.parse(text) as T & { error?: string; field?: string }) : null;
	} catch {
		return {
			ok: false,
			status: 0,
			data: null,
			error: NETWORK_ERROR,
			field: null,
			refused: false
		};
	}

	const required = response.headers.get(REQUIRED_LEVEL_HEADER) as AuthLevel | null;
	const refused = !response.ok && required !== null;
	if (refused && onRefusal) {
		await onRefusal(required, upgradePaths(response));
	}

	return {
		ok: response.ok,
		status: response.status,
		data: body,
		error: body?.error ?? null,
		field: body?.field ?? null,
		refused
	};
}
