/**
 * App-wide transient notices, surfaced as toasts.
 *
 * Backed by Ark UI's Toast primitive (`@ark-ui/svelte`), which owns the queue,
 * auto-dismiss timers, stacking, pause-on-hover and accessible semantics, so we
 * do not hand-roll any of that. Callers keep the small imperative API below;
 * the renderer is `<Toaster>`, mounted once in the layout.
 */
import { createToaster } from '@ark-ui/svelte';
import { tick } from 'svelte';

export type NoticeKind = 'error' | 'success' | 'info';

/**
 * The single toaster instance. Notices stack at the top of the account
 * pages (where the content begins) and their countdown pauses while the tab is
 * hidden, so a notice is never missed by an away user.
 */
export const toaster = createToaster({
	placement: 'top',
	overlap: true,
	gap: 10,
	// Without this, Ark UI's default per-type durations (2s for success) make
	// confirmations too easy to miss.
	duration: 6000,
	removeDelay: 220,
	pauseOnPageIdle: true,
	offsets: '14px'
});

/**
 * Raises a toast.
 *
 * Deferred by a tick: Ark UI's store flushes synchronously, and a page that
 * raises a notice during its own initialisation (e.g. the signed-out notice on
 * the sign-in page) would otherwise write to the store mid-render, re-entering
 * Svelte's flush until the stack overflows.
 */
export function notify(kind: NoticeKind, message: string): void {
	void tick().then(() => toaster.create({ type: kind, title: message }));
}

/** Shared copy for an unreachable relay, so the wording stays consistent. */
export function networkError(): void {
	notify('error', 'We could not reach the server. Check your connection and try again.');
}

/** Shown when the session is gone or was rejected (typically a 401). */
export function sessionExpired(): void {
	notify('error', 'Your session has expired. Please sign in again.');
}
