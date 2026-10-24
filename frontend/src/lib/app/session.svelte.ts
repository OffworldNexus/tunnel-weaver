/**
 * The signed-in identity, owned by the root layout.
 *
 * The session cookie is httpOnly, so the browser can only learn who is signed
 * in by asking the relay. The root layout creates one `Session`, re-reads it on
 * mount and — awaited — on every navigation (`onNavigate`), and publishes it
 * through Svelte context; every page reads it with `useSession()` instead of
 * issuing a request of its own. One probe per navigation is what keeps the
 * whole app — the console, the auth pages and the public landing page —
 * agreeing about who is signed in.
 */
import { getContext, setContext } from 'svelte';

import { api } from '#lib/account/api';

export interface Me {
	id: number;
	name: string;
	/** Empty for an account with no email identity. */
	email: string;
	/** Whether the account has a password credential; not every sign-in method needs one. */
	has_password: boolean;
}

/**
 * `loading` only until the first probe settles. Later probes keep the last
 * settled status, so a same-app navigation never flashes the holding gate.
 */
export type SessionStatus = 'loading' | 'ready' | 'error';

const KEY = Symbol('weaver.session');

/**
 * The one session for the running app. Read reactively (`session.user`); the
 * root layout is the only thing that writes it, through `refresh()`.
 */
export class Session {
	/** The signed-in account, or null when signed out. */
	user = $state<Me | null>(null);
	/** Whether the first probe has settled, and whether it failed. */
	status = $state<SessionStatus>('loading');
	/** Why the last probe failed; shown by the root layout's error gate. */
	error = $state('');

	/**
	 * Re-reads the session from the relay. Called on mount and, awaited, on
	 * every navigation. The first call moves `loading` to a settled status;
	 * later calls leave `loading` untouched so the holding gate never reappears
	 * mid-session. A failed probe fails loudly: it lands on `error` rather than
	 * being mistaken for a signed-out visitor.
	 */
	async refresh(): Promise<void> {
		const res = await api<Me>('/api/account/me');
		if (res.ok && res.data) {
			this.user = res.data;
			this.status = 'ready';
			this.error = '';
		} else if (res.status === 401) {
			this.user = null;
			this.status = 'ready';
			this.error = '';
		} else {
			this.user = null;
			this.status = 'error';
			this.error = res.error ?? 'We could not verify your session. Try again.';
		}
	}
}

/** Creates the session and publishes it to every descendant. Root layout only. */
export function provideSession(): Session {
	const session = new Session();
	setContext(KEY, session);
	return session;
}

/**
 * Reads the session published by the root layout. Throws when read outside its
 * subtree — a missing provider is a programming error, not a runtime state.
 */
export function useSession(): Session {
	const session = getContext<Session | undefined>(KEY);
	if (!session) {
		throw new Error('useSession() must be called under the root layout, which provides it.');
	}
	return session;
}
