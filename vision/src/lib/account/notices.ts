/**
 * App-wide transient notices, rendered as Ark UI toasts by `<Toaster>` in the
 * root layout.
 */
import { createToaster } from '@ark-ui/svelte';
import { tick } from 'svelte';

export const toaster = createToaster({
	placement: 'top',
	overlap: true,
	gap: 10,
	// Ark UI's default for success (2s) is too easy to miss.
	duration: 6000,
	removeDelay: 220,
	pauseOnPageIdle: true,
	offsets: '14px'
});

/**
 * Raises a toast. Deferred by a tick: Ark UI's store flushes synchronously, and
 * a page raising a notice during its own initialisation would otherwise write
 * to the store mid-render and re-enter Svelte's flush until the stack overflows.
 */
export function notify(kind: 'error' | 'success', message: string): void {
	void tick().then(() => toaster.create({ type: kind, title: message }));
}
