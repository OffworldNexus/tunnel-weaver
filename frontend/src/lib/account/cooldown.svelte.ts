import { onDestroy } from 'svelte';

import { ensureConfig } from '#lib/account/config.svelte';

/**
 * The re-send cooldown a page counts down after a code is sent, matching the
 * relay's own `resend_cooldown_secs`. Call it during component setup: the
 * timer stops with the component.
 */
export function useCooldown() {
	let remaining = $state(0);
	let timer: ReturnType<typeof setInterval> | undefined;

	onDestroy(() => clearInterval(timer));

	return {
		/** Seconds until a re-send is allowed; `0` when it is. */
		get remaining(): number {
			return remaining;
		},
		/** Restarts the countdown. */
		async start(): Promise<void> {
			const cfg = await ensureConfig().catch(() => null);
			clearInterval(timer);
			remaining = cfg?.resend_cooldown_secs ?? 60;
			timer = setInterval(() => {
				remaining -= 1;
				if (remaining <= 0) {
					clearInterval(timer);
				}
			}, 1000);
		}
	};
}
