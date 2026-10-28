/** State carried across route changes, kept in Web Storage so a reload keeps it. */

function stored<T extends object>(storage: Storage, key: string) {
	const load = (): Partial<T> => JSON.parse(storage.getItem(key) ?? '{}') as Partial<T>;
	return {
		load,
		save: (patch: Partial<T>) => storage.setItem(key, JSON.stringify({ ...load(), ...patch })),
		clear: () => storage.removeItem(key)
	};
}

/**
 * The account flow, tab-scoped: the signup flow id and address being verified,
 * the completion token, a one-shot success notice for the sign-in page, and the
 * second factor the person chose on the way-chooser.
 */
export const flow = stored<{
	flow: string;
	email: string;
	completion_token: string;
	notice: string;
	/**
	 * The second factor the way-chooser sent the person to the code step for.
	 * Empty means "whatever the relay offers first". It lives here rather than in
	 * the URL so a reload of the code step keeps the choice, and it is cleared
	 * once a code is accepted so the *next* sign-in starts on what the relay
	 * offers rather than on last time's choice.
	 */
	second_factor: string;
}>(sessionStorage, 'weaver.account.state');

/**
 * A pending pairing, shared across tabs: the handle (its fragment is stripped
 * on mount and cannot survive a navigation) and whether signing in should
 * return to `/pair`. Shared because the verification email of the sign-up
 * detour usually opens in a new tab.
 */
export const pairing = stored<{ handle: string; detour: boolean }>(localStorage, 'weaver.pairing');
