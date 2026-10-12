/**
 * The signed-in identity, shared across the `/app` shell.
 *
 * `GET /api/account/me` is the authoritative session check. The `/app` layout
 * loads it once and publishes it here so child pages (the Security page in
 * particular) read the same identity instead of each re-fetching it.
 */
import { writable } from 'svelte/store';
import { api, messageOf } from '#lib/account/api';

export interface Me {
	id: number | string;
	name: string;
	email: string | null;
	/** Whether the account has a live password credential (WVR-50). */
	has_password: boolean;
}

/** The confirmed identity, or `null` before load / after a rejected session. */
export const me = writable<Me | null>(null);

/** The outcome of a session check, so the caller can react to the reason. */
export type MeOutcome =
	| { status: 'ok'; me: Me }
	| { status: 'unauthenticated' }
	| { status: 'error'; message: string };

/**
 * Confirms the session with the relay and publishes the result.
 *
 * A 401 is folded into `unauthenticated` (a stale session is not a failure); a
 * transport error keeps its own outcome so the layout can offer a retry without
 * treating it as a sign-out.
 */
export async function ensureMe(): Promise<MeOutcome> {
	try {
		const result = await api<Me>('/api/account/me');
		if (result.ok && result.data) {
			me.set(result.data);
			return { status: 'ok', me: result.data };
		}
		if (result.status === 401) {
			me.set(null);
			return { status: 'unauthenticated' };
		}
		me.set(null);
		return {
			status: 'error',
			message: messageOf(result.data, 'We could not verify your session. Try again.')
		};
	} catch {
		me.set(null);
		return { status: 'error', message: 'We could not reach the server.' };
	}
}
