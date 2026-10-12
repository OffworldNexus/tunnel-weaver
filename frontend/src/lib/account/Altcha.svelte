<script lang="ts">
	import { ensureConfig } from '#lib/account/config';
	import { loadAltcha } from '#lib/account/altcha';

	/** The signed purpose the challenge is bound to. */
	export let purpose: 'login' | 'signup' | 'reset';
	/** Called with the solved ALTCHA payload from the `verified` event. */
	export let onSolved: (payload: string) => void = () => {};
	/** Called when a previously solved proof has expired. */
	export let onExpired: () => void = () => {};
	/** Bump this number to re-solve after a single-use proof was consumed. */
	export let resetSignal = 0;

	type AltchaState = 'unverified' | 'verifying' | 'verified' | 'expired' | 'error';

	interface AltchaWidget extends HTMLElement {
		reset?: () => void;
		verify?: () => Promise<unknown> | unknown;
	}

	let element: AltchaWidget | null = null;
	let challenge = '';
	let ready = false;
	let failed = false;
	let reloadKey = 0;
	let status: 'loading' | 'solving' | 'ready' | 'error' = 'loading';

	$: {
		// Re-run whenever `reloadKey` changes so the retry control can remount
		// the widget against a fresh challenge URL.
		reloadKey;
		void start();
	}

	$: if (resetSignal > 0) solve();

	async function start(): Promise<void> {
		failed = false;
		ready = false;
		status = 'loading';
		try {
			const cfg = await ensureConfig();
			await loadAltcha(cfg.altcha_assets_base);
			relabel();
			challenge = `${cfg.altcha_challenge_url}?purpose=${purpose}`;
			ready = true;
		} catch {
			failed = true;
			status = 'error';
		}
	}

	/** Reword the widget label without clobbering the rest of the map. */
	function relabel(): void {
		const store = globalThis.$altcha?.i18n;
		const current = store?.get?.('en') ?? {};
		store?.set?.('en', { ...current, label: "I'm well-intentioned" });
	}

	/**
	 * Reset and solve a fresh proof. A proof is single-use server-side, so the
	 * parent bumps `resetSignal` after every attempt.
	 */
	export function solve(): void {
		if (!element) return;
		try {
			element.reset?.();
		} catch {
			// The widget may not be mounted yet; verify() below still runs.
		}
		status = 'solving';
		void element.verify?.();
	}

	/** Attaches the widget's `verified` / `statechange` listeners. */
	function wire(node: AltchaWidget) {
		const onVerified = (event: Event) => {
			const detail = (event as CustomEvent<{ payload: string }>).detail;
			status = 'ready';
			onSolved(detail.payload);
		};
		const onStateChange = (event: Event) => {
			const state = (event as CustomEvent<{ state: AltchaState }>).detail?.state;
			if (state === 'verifying') {
				status = 'solving';
			} else if (state === 'verified') {
				status = 'ready';
			} else if (state === 'expired') {
				// A proof expired before it was used: reset and re-solve.
				status = 'solving';
				onExpired();
				solve();
			} else if (state === 'error') {
				status = 'error';
			}
		};
		node.addEventListener('verified', onVerified);
		node.addEventListener('statechange', onStateChange);
		return {
			destroy() {
				node.removeEventListener('verified', onVerified);
				node.removeEventListener('statechange', onStateChange);
			}
		};
	}
</script>

<div class="altcha">
	<p class="altcha-state" data-state={status} aria-live="polite">
		<span class="altcha-state__dot" aria-hidden="true"></span>
		<span>
			{#if status === 'ready'}
				Ready to go.
			{:else if status === 'solving'}
				Just a moment…
			{:else if status === 'error'}
				Something went wrong.
			{:else}
				One moment…
			{/if}
		</span>
		{#if status === 'error'}
			<button type="button" class="linklike" on:click={() => (reloadKey += 1)}>Try again</button>
		{/if}
	</p>

	{#if ready}
		<!-- Self-hosted, vendored widget. `challenge` is the real attribute (not
		     `challengeurl`); it is driven programmatically and rendered
		     invisibly — our own status line is the only visible chrome. -->
		<altcha-widget
			bind:this={element}
			use:wire
			class="altcha-widget"
			challenge={challenge}
			name="altcha"
			auto="onload"
			display="bar"
			configuration={'{"hideFooter":true,"hideLogo":true}'}
			aria-hidden="true"
			inert
		></altcha-widget>
	{/if}
</div>

<style lang="scss">
	.altcha {
		display: flex;
		flex-direction: column;
		gap: 8px;
		margin-top: 4px;
	}

	.altcha-state {
		display: flex;
		align-items: center;
		gap: 8px;
		color: var(--tw-muted);
		font-size: 14px;
	}

	.altcha-state__dot {
		width: 8px;
		height: 8px;
		flex: none;
		border-radius: 50%;
		background: var(--tw-muted);
	}

	.altcha-state[data-state='solving'] .altcha-state__dot {
		background: var(--tw-focus);
	}

	.altcha-state[data-state='ready'] .altcha-state__dot {
		background: var(--tw-success);
	}

	.altcha-state[data-state='error'] {
		color: var(--tw-danger);
	}

	.altcha-state[data-state='error'] .altcha-state__dot {
		background: var(--tw-danger);
	}

	/* The vendored widget is driven programmatically and rendered invisibly; the
	   status line above is the only chrome the user sees. */
	.altcha-widget {
		position: absolute;
		width: 1px;
		height: 1px;
		padding: 0;
		margin: -1px;
		overflow: hidden;
		clip-path: inset(50%);
		border: 0;
		white-space: nowrap;
	}

	altcha-widget {
		/* Blend the upstream widget into the relay's palette, in case its chrome
		   is ever surfaced. */
		display: block;
		width: 100%;
		max-width: 420px;
		--altcha-border-radius: var(--tw-radius);
		--altcha-border-color: var(--tw-border);
		--altcha-color-base: var(--tw-well);
		--altcha-color-base-content: var(--tw-text);
		--altcha-color-primary: var(--tw-accent);
		--altcha-max-width: 100%;
	}
</style>
