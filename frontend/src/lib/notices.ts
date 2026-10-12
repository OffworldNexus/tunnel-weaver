/**
 * App-wide transient notices: network failures, session expiry, confirmations.
 *
 * Notices live in a store so any route can raise one through the single
 * `<Notice>` renderer mounted in the layout, without owning that UI itself.
 * Each notice carries a monotonic id so the list can be keyed and dismissed
 * individually rather than cleared wholesale.
 */
import { writable } from 'svelte/store';

export type NoticeKind = 'error' | 'success' | 'info';

export interface Notice {
	id: number;
	kind: NoticeKind;
	message: string;
}

export const notices = writable<Notice[]>([]);

let counter = 0;

/** Push a notice onto the stack; the id lets the renderer key and dismiss it. */
export function notify(kind: NoticeKind, message: string): void {
	const id = ++counter;
	notices.update((list) => [...list, { id, kind, message }]);
}

/** Remove a single notice by id. */
export function dismiss(id: number): void {
	notices.update((list) => list.filter((notice) => notice.id !== id));
}

/** Shared copy for an unreachable relay, so the wording stays consistent. */
export function networkError(): void {
	notify('error', 'We could not reach the server. Check your connection and try again.');
}

/** Shown when the session is gone or was rejected (typically a 401). */
export function sessionExpired(): void {
	notify('error', 'Your session has expired. Please sign in again.');
}
