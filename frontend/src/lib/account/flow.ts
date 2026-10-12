/**
 * In-memory, tab-scoped state carried across SPA route changes (signup flow id,
 * the address being verified, the completion token, and one-shot notices).
 *
 * Session storage is used so a page refresh mid-flow does not lose the token
 * the server just handed back.
 */

const KEY = 'weaver.account.state';

export interface FlowState {
	flow?: string;
	email?: string;
	name?: string;
	completion_token?: string;
	notice?: string;
	noticeKind?: 'success' | 'info' | 'error';
}

export function loadFlow(): FlowState {
	try {
		const raw = sessionStorage.getItem(KEY);
		return raw ? (JSON.parse(raw) as FlowState) : {};
	} catch {
		return {};
	}
}

export function saveFlow(patch: FlowState): void {
	try {
		sessionStorage.setItem(KEY, JSON.stringify({ ...loadFlow(), ...patch }));
	} catch {
		// Storage can be unavailable (private mode); flows still work in-memory
		// for the current page, they just do not survive a reload.
	}
}

export function clearFlow(): void {
	try {
		sessionStorage.removeItem(KEY);
	} catch {
		// ignore
	}
}
