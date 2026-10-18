/**
 * The pairing detour's state (WVR-13), shared across tabs of one browser.
 *
 * When someone opens a pairing link without an account, they leave `/pair` for
 * sign-up / sign-in and must come back. Two things have to survive that:
 *
 *  - the **next** target, so signing in returns to the confirmation; and
 *  - the **handle**, which the link carried in the URL fragment — a fragment is
 *    stripped on mount and cannot survive a navigation.
 *
 * `localStorage`, not the tab-scoped session storage the account flow uses,
 * precisely because the verification email usually opens in a *new tab*: a
 * fresh tab shares localStorage but not sessionStorage. The handle is a
 * capability, but it dies with the terminal's channel, so a lingering value is
 * inert.
 */

const KEY = 'weaver.pairing';

export interface PairingState {
	/** The pending pairing's handle. */
	handle?: string;
	/** A same-origin path to return to after signing in (`/pair`). */
	next?: string;
}

export function loadPairing(): PairingState {
	try {
		const raw = localStorage.getItem(KEY);
		return raw ? (JSON.parse(raw) as PairingState) : {};
	} catch {
		return {};
	}
}

export function savePairing(patch: PairingState): void {
	try {
		localStorage.setItem(KEY, JSON.stringify({ ...loadPairing(), ...patch }));
	} catch {
		// Storage can be unavailable (private mode); the person can re-open the
		// original link, which still works while the terminal waits.
	}
}

export function clearPairing(): void {
	try {
		localStorage.removeItem(KEY);
	} catch {
		// ignore
	}
}
