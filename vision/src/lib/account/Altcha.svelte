<script lang="ts">
	/**
	 * The proof-of-work gate. The vendored widget solves invisibly; the status
	 * line is the only chrome. `payload` holds a solved proof, or `''` while none
	 * is ready.
	 */
	import { loadAltcha } from '#lib/account/altcha';
	import { ensureConfig } from '#lib/account/config';

	/** The signed purpose the challenge is bound to. */
	export let purpose: 'login' | 'signup' | 'reset';
	export let payload = '';

	interface AltchaWidget extends HTMLElement {
		reset: () => void;
		verify: () => Promise<unknown>;
	}

	let element: AltchaWidget | null = null;
	let challenge = '';
	let status: 'loading' | 'solving' | 'ready' | 'error' = 'loading';

	async function start(): Promise<void> {
		status = 'loading';
		try {
			const cfg = await ensureConfig();
			await loadAltcha(cfg.altcha_assets_base);
			challenge = `${cfg.altcha_challenge_url}?purpose=${purpose}`;
		} catch {
			status = 'error';
		}
	}

	void start();

	/** Solves a fresh proof. A proof is single use, so call this after every attempt. */
	export function reset(): void {
		payload = '';
		if (!element) {
			return;
		}
		element.reset();
		status = 'solving';
		void element.verify();
	}

	function retry(): void {
		if (element) {
			reset();
		} else {
			void start();
		}
	}

	function wire(node: AltchaWidget) {
		const onVerified = (event: Event) => {
			status = 'ready';
			payload = (event as CustomEvent<{ payload: string }>).detail.payload;
		};
		const onStateChange = (event: Event) => {
			const state = (event as CustomEvent<{ state: string }>).detail.state;
			if (state === 'verifying') {
				status = 'solving';
			} else if (state === 'expired') {
				reset();
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

<p class="altcha" data-state={status} aria-live="polite">
	<span class="altcha__dot" aria-hidden="true"></span>
	<span>
		{#if status === 'ready'}
			Ready to go.
		{:else if status === 'error'}
			Something went wrong.
		{:else}
			Just a moment…
		{/if}
	</span>
	{#if status === 'error'}
		<button type="button" class="linklike" on:click={retry}>Try again</button>
	{/if}
</p>

{#if challenge}
	<altcha-widget
		bind:this={element}
		use:wire
		class="altcha-widget"
		{challenge}
		name="altcha"
		auto="onload"
		display="bar"
		configuration={'{"hideFooter":true,"hideLogo":true}'}
		aria-hidden="true"
		inert
	></altcha-widget>
{/if}

<style lang="scss">
	.altcha {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-top: 4px;
		color: var(--tw-muted);
		font-size: 14px;
	}

	.altcha__dot {
		width: 8px;
		height: 8px;
		flex: none;
		border-radius: 50%;
		background: var(--tw-muted);
	}

	.altcha[data-state='solving'] .altcha__dot {
		background: var(--tw-focus);
	}

	.altcha[data-state='ready'] .altcha__dot {
		background: var(--tw-success);
	}

	.altcha[data-state='error'] {
		color: var(--tw-danger);
	}

	.altcha[data-state='error'] .altcha__dot {
		background: var(--tw-danger);
	}

	.altcha-widget {
		position: absolute;
		width: 1px;
		height: 1px;
		overflow: hidden;
		clip-path: inset(50%);
	}
</style>
