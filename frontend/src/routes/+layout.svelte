<script lang="ts">
	import '../styles/global.scss';

	import { onMount, type Snippet } from 'svelte';

	import { ensureConfig } from '#lib/account/config.svelte';
	import { provideSession } from '#lib/app/session.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import Toaster from '#lib/ui/Toaster.svelte';
	import { onNavigate } from '$app/navigation';

	interface Props {
		children: Snippet;
	}

	let { children }: Props = $props();

	const session = provideSession();

	// The session lives in an httpOnly cookie, so the relay is the only source
	// of truth. `onNavigate` runs on every in-app navigation, and because the
	// callback returns a promise SvelteKit waits for it before completing the
	// navigation — so the page the app lands on is decided against a freshly
	// read session, never the one the previous page was still showing. (This is
	// why it is `onNavigate` and not `beforeNavigate`: only the former is
	// awaited. A stale or expired session must never reach a guard or a loader.)
	onNavigate(async () => {
		await session.refresh();
	});

	// `onNavigate` is skipped for the initial full-page load, so the first probe
	// happens on mount; the holding gate below covers it.
	onMount(() => {
		void session.refresh();
	});

	// Warm the constants; the pages that need them report a failure themselves.
	ensureConfig().catch(() => {});
</script>

<a class="skip-link" href="#main">Skip to content</a>
<Toaster />

{#if session.status === 'loading'}
	<!-- The single session boundary: nothing renders until we know who is
	     signed in, so no page ever has to guess. -->
	<Page labelledby="checking-title" center>
		<h1 id="checking-title">One moment</h1>
		<p class="lede" role="status">Checking your session…</p>
	</Page>
{:else if session.status === 'error'}
	<!-- Fail loudly: an unreachable relay is not a signed-out visitor. -->
	<Page labelledby="session-error-title" center>
		<h1 id="session-error-title">We could not reach the server</h1>
		<p class="notice-error" role="alert">{session.error}</p>
		<div class="actions">
			<Keycap type="button" onclick={() => session.refresh()} wide>Try again</Keycap>
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
