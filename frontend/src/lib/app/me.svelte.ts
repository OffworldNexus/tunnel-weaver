/**
 * The signed-in identity. `GET /api/account/me` is the session check; the
 * `/app` layout and the pairing page run it and publish the result here.
 */
import { api } from '#lib/account/api';

export interface Me {
	id: number;
	name: string;
	/** Empty for an account with no email identity. */
	email: string;
	/** Whether the account has a password credential; not every sign-in method needs one. */
	has_password: boolean;
}

export const me = $state<{ value: Me | null }>({ value: null });

export type MeOutcome =
	{ status: 'ok' } | { status: 'unauthenticated' } | { status: 'error'; message: string };

export async function ensureMe(): Promise<MeOutcome> {
	const res = await api<Me>('/api/account/me');
	me.value = res.ok ? res.data : null;
	if (res.ok) {
		return { status: 'ok' };
	}
	if (res.status === 401) {
		return { status: 'unauthenticated' };
	}
	return { status: 'error', message: res.error ?? 'We could not verify your session. Try again.' };
}
