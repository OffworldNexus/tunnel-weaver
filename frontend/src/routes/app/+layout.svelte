<script lang="ts">
	/**
	 * The signed-in console layout: it mounts the shell for every `/app` route.
	 * The root layout settles the session before this layout renders, so a
	 * signed-out visitor here (an expired session, or a link opened after
	 * signing out) is simply sent to sign-in.
	 */
	import type { Snippet } from 'svelte';

	import { notify } from '#lib/account/notices';
	import { useSession } from '#lib/app/session.svelte';
	import { meta } from '#lib/console/meta.svelte';
	import Shell from '#lib/console/Shell.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	interface Props {
		children: Snippet;
	}

	let { children }: Props = $props();

	const session = useSession();

	// The session probe lives in the root layout and runs on every navigation;
	// when it settles without a user, the console is not a place to be.
	$effect(() => {
		if (!session.user) {
			notify('error', 'Your session has expired. Please sign in again.');
			void goto(resolve('/(auth)/sign-in'), { replace: true });
		}
	});
</script>

<svelte:head>
	<title>Console · Tunnel Weaver</title>
</svelte:head>

{#if session.user}
	<Shell title={meta.title} subtitle={meta.subtitle} crumbs={meta.crumbs}>
		{@render children()}
	</Shell>
{:else}
	<Page labelledby="app-title">
		<h1 id="app-title">Your account</h1>
		<p class="lede" role="status">Checking your session…</p>
	</Page>
{/if}
