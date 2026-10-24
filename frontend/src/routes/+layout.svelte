<script lang="ts">
	import '../styles/global.scss';

	import { ensureConfig } from '#lib/account/config.svelte';
	import { provideSession } from '#lib/app/session.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import Toaster from '#lib/ui/Toaster.svelte';
	import { refreshAll } from '$app/navigation';

	import type { LayoutProps } from './$types';

	let { data, children }: LayoutProps = $props();

	// The root `+layout.ts` load already read the session — before this route's
	// own loads ran — so the whole app shares one freshly read identity.
	provideSession(() => data.session);

	// Warm the constants; the pages that need them report a failure themselves.
	ensureConfig().catch(() => {});
</script>

<a class="skip-link" href="#main">Skip to content</a>
<Toaster />

{#if data.error}
	<!-- Fail loudly: an unreachable relay is not a signed-out visitor. -->
	<Page labelledby="session-error-title" center>
		<h1 id="session-error-title">We could not reach the server</h1>
		<p class="notice-error" role="alert">{data.error}</p>
		<div class="actions">
			<Keycap type="button" onclick={() => refreshAll()} wide>Try again</Keycap>
		</div>
	</Page>
{:else}
	{@render children()}
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
