<script lang="ts">
	/**
	 * The signed-in console layout: it confirms the session once on entry and
	 * mounts the shell for every `/app` route. A signed-out visitor is sent to
	 * sign-in; until the session is known a bare holding page is shown.
	 */
	import { onMount } from 'svelte';

	import { notify } from '#lib/account/notices';
	import { ensureMe, me } from '#lib/app/me';
	import { meta } from '#lib/console/meta';
	import Shell from '#lib/console/Shell.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

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
	<title>Console · Tunnel Weaver</title>
</svelte:head>

{#if $me}
	<Shell title={$meta.title} subtitle={$meta.subtitle} crumbs={$meta.crumbs}>
		<slot />
	</Shell>
{:else}
	<Page labelledby="app-title">
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
	</Page>
{/if}
