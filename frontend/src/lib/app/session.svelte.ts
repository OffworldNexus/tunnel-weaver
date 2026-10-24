/**
 * The signed-in identity, read once per navigation by the root layout's `load`
 * and shared with every page through Svelte context.
 *
 * The session cookie is httpOnly, so the browser can only learn who is signed
 * in by asking the relay. The root layout's load runs before the destination's
 * own loads, and the protected page loads `await parent()` — so
 * `GET /api/account/me` is the first request a navigation issues, and no page
 * fetches its own data before the session is known. Pages read the result with
 * `useSession()` instead of issuing a query of their own.
 */
import { getContext, setContext } from 'svelte';

export interface Me {
	id: number;
	name: string;
	/** Empty for an account with no email identity. */
	email: string;
	/** Whether the account has a password credential; not every sign-in method needs one. */
	has_password: boolean;
}

export interface Session {
	/** The signed-in account, or null when signed out. */
	readonly user: Me | null;
}

const KEY = Symbol('weaver.session');

/**
 * Publishes the session read from the root layout's `load`. The accessor — not
 * a snapshot — is kept so a navigation that replaces the layout data is seen by
 * every reader. Root layout only.
 */
export function provideSession(user: () => Me | null): Session {
	const session: Session = {
		get user() {
			return user();
		}
	};
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
