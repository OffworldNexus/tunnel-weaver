/**
 * The Security page's data: the one endpoint behind it (WVR-166).
 *
 * What an account signs in with — whether a password is set, its passkeys, its
 * authenticator apps — is one screen of the console, so it is one read. The page
 * gets it through its loader and every action invalidates that load, rather than
 * each panel keeping a copy of its own list and refreshing it by hand.
 */
import { api } from '#lib/account/api';

/** One of the account's passkeys, as the relay lists it (WVR-163). */
export interface PasskeyView {
	id: number;
	/** What the person called it; empty when they did not name it. */
	name: string;
	transports: string[];
	created_at: number;
	last_used_at: number | null;
}

/**
 * One of the account's authenticator apps, as the relay lists it (WVR-166).
 *
 * Only confirmed apps are listed: an enrolment that was begun and never proved
 * is not a factor, and the relay's sweep deletes the ones nobody finished.
 */
export interface AuthenticatorApp {
	id: number;
	/** What the person called it; empty when they did not name it. */
	name: string;
	created_at: number;
	/** Absent until a code from this app has signed someone in. */
	last_used_at: number | null;
}

/** Everything the Security page shows. */
export interface SecurityOverview {
	/** Whether the account holds a live password credential. */
	has_password: boolean;
	passkeys: PasskeyView[];
	authenticator_apps: AuthenticatorApp[];
}

/** Reads the page's data. */
export function loadSecurity() {
	return api<SecurityOverview>('GET', '/api/account/security');
}
