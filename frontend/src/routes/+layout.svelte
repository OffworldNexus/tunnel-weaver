<script lang="ts">
	import '../styles/global.scss';

	import { ensureConfig } from '#lib/account/config.svelte';
	import { provideSession } from '#lib/app/session.svelte';
	import { stepUp } from '#lib/app/stepup.svelte';
	import ConfirmPasswordDialog from '#lib/ui/ConfirmPasswordDialog.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import Toaster from '#lib/ui/Toaster.svelte';

	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();

	// The root `+layout.ts` load opened the session stream and waited for its
	// first frame, so the whole app shares one live identity.
	const session = provideSession();

	// Warm the constants; the pages that need them report a failure themselves.
	ensureConfig().catch(() => {});
</script>

<a class="skip-link" href="#main">Skip to content</a>
<Toaster />

<!--
	The inline escalation popin lives here, once, so any action on any
	signed-in page can have a level re-proven without owning a form of its
	own — and so the page it happened on is still there afterwards.
-->
<ConfirmPasswordDialog
	bind:open={stepUp.open}
	error={stepUp.error}
	busy={stepUp.busy}
	passkeyAvailable={stepUp.passkeyAvailable}
	onConfirm={(password: string) => stepUp.submit(password)}
	onPasskey={() => stepUp.submitPasskey()}
	onClose={() => stepUp.cancel()}
/>

{#if session.ready}
	{@render children()}
{:else if session.error}
	<!-- Fail loudly: an unreachable relay is not a signed-out visitor. -->
	<Page labelledby="session-error-title" center>
		<h1 id="session-error-title">We could not reach the server</h1>
		<p class="notice-error" role="alert">{session.error}</p>
		<div class="actions">
			<Keycap type="button" onclick={() => session.restart()} wide>Try again</Keycap>
		</div>
	</Page>
{/if}

<style lang="scss">
	.skip-link {
		position: absolute;
		left: 50%;
		top: -60px;
		transform: translateX(-50%);
		z-index: 30;
		padding: 10px 16px;
		border-radius: 0 0 var(--tw-radius) var(--tw-radius);
		background: var(--tw-text);
		color: var(--tw-deck);
		text-decoration: none;
		transition: top 120ms ease;
	}

	.skip-link:focus {
		top: 0;
	}

	@media (prefers-reduced-motion: reduce) {
		.skip-link {
			transition: none;
		}
	}
</style>
