<script lang="ts">
	/**
	 * Signed-in shell for every `/app` route.
	 *
	 * Confirms the session once on entry and owns the shared chrome — the page
	 * shell, the account nav, and the loading/expired states — so each page below
	 * renders only its own content. A 401 is a stale session, not a failure:
	 * notify and return to sign-in.
	 */
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { networkError, sessionExpired } from '#lib/account/notices';
	import { ensureMe, me } from '#lib/app/me';
	import { href } from '#lib/app/paths';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';

	let checking = true;
	let error = '';

	onMount(() => {
		void check();
	});

	// Confirms the session with the relay and publishes `me` for the pages below.
	async function check() {
		checking = true;
		error = '';
		const outcome = await ensureMe();
		if (outcome.status === 'unauthenticated') {
			sessionExpired();
			await goto(href('/sign-in'));
		} else if (outcome.status === 'error') {
			error = outcome.message;
			networkError();
		}
		checking = false;
	}

	$: accountPath = href('/app');
	$: securityPath = href('/app/security');
	$: path = page.url.pathname;
</script>

<svelte:head>
	<title>Your account · Tunnel Weaver</title>
</svelte:head>

<Page center={false} labelledby="app-title">
	{#if $me}
		<nav class="nav" aria-label="Account">
			<a href={accountPath} aria-current={path === accountPath ? 'page' : undefined}>
				Your account
			</a>
			<a href={securityPath} aria-current={path.startsWith(securityPath) ? 'page' : undefined}>
				Security
			</a>
		</nav>

		<slot />
	{:else}
		<h1 id="app-title">Your account</h1>
		<p class="lede" aria-live="polite">
			{#if checking}Checking your session…{:else}You are not signed in.{/if}
		</p>
		{#if error}
			<p class="notice-error" role="alert" aria-live="assertive">{error}</p>
		{/if}
		<div class="actions">
			<Keycap type="button" loading={checking} onclick={check} wide>Check authentication</Keycap>
			<Keycap wide variant="ghost" href={href('/sign-in')}>Back to sign in</Keycap>
		</div>
	{/if}
</Page>

<style lang="scss">
	/* The account sections. A row on small screens; the drawn desktop page puts
	   navigation in a left column, which the layout converges toward later. */
	.nav {
		display: flex;
		flex-wrap: wrap;
		gap: 8px 20px;
		margin-bottom: 24px;
		padding-bottom: 12px;
		border-bottom: 1.5px solid var(--tw-border);
	}

	.nav a {
		/* The drawn navigation rows are 44–48px tall; the bare text is only
		   ~26px, so reserve the tap-target height here. */
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
