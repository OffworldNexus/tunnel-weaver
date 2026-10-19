<script lang="ts">
	/**
	 * The signed-in shell for every `/app` route: confirms the session once on
	 * entry and owns the page chrome and the account nav. A signed-out visitor
	 * is sent to sign-in.
	 */
	import { onMount } from 'svelte';

	import { notify } from '#lib/account/notices';
	import { ensureMe, me } from '#lib/app/me';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';

	const accountPath = resolve('/app');
	const securityPath = resolve('/app/security');

	let checking = true;
	let error = '';

	async function check() {
		checking = true;
		error = '';
		const outcome = await ensureMe();
		if (outcome.status === 'unauthenticated') {
			notify('error', 'Your session has expired. Please sign in again.');
			await goto(resolve('/sign-in'));
		} else if (outcome.status === 'error') {
			error = outcome.message;
		}
		checking = false;
	}

	onMount(check);
</script>

<svelte:head>
	<title>Your account · Tunnel Weaver</title>
</svelte:head>

<Page center={false} labelledby="app-title">
	{#if $me}
		<nav class="nav" aria-label="Account">
			<a href={accountPath} aria-current={page.url.pathname === accountPath ? 'page' : undefined}>
				Your account
			</a>
			<a
				href={securityPath}
				aria-current={page.url.pathname.startsWith(securityPath) ? 'page' : undefined}
			>
				Security
			</a>
		</nav>

		<slot />
	{:else}
		<h1 id="app-title">Your account</h1>
		{#if checking}
			<p class="lede" aria-live="polite">Checking your session…</p>
		{:else if error}
			<p class="notice-error" role="alert">{error}</p>
			<div class="actions">
				<Keycap type="button" onclick={check} wide>Try again</Keycap>
				<Keycap wide variant="ghost" href={resolve('/sign-in')}>Back to sign in</Keycap>
			</div>
		{/if}
	{/if}
</Page>

<style lang="scss">
	.nav {
		display: flex;
		flex-wrap: wrap;
		gap: 8px 20px;
		margin-bottom: 24px;
		padding-bottom: 12px;
		border-bottom: 1.5px solid var(--tw-border);
	}

	.nav a {
		display: inline-flex;
		align-items: center;
		min-height: 44px;
		color: var(--tw-muted);
		font-weight: 700;
		text-decoration: none;
	}

	.nav a:hover {
		text-decoration: underline;
	}

	.nav a[aria-current='page'] {
		color: var(--tw-text);
	}
</style>
