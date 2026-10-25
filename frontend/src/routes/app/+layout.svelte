<script lang="ts">
	/**
	 * The signed-in console layout: it mounts the shell for every `/app` route.
	 *
	 * It follows the session stream: the console needs `strong`, so whenever the
	 * level it holds is lower — on arrival, or once the relay has said it fell —
	 * the person is sent up the way the stream names (to sign-in once the session
	 * is gone). Because the relay reports a fall a little early, that happens
	 * before the strict level is gone rather than after it.
	 */
	import type { Snippet } from 'svelte';

	import { atLeast, useSession } from '#lib/app/session.svelte';
	import { climb } from '#lib/app/upgrade';
	import { meta } from '#lib/console/meta.svelte';
	import Shell from '#lib/console/Shell.svelte';
	import Page from '#lib/ui/Page.svelte';

	interface Props {
		children: Snippet;
	}

	let { children }: Props = $props();

	const session = useSession();

	$effect(() => {
		if (!atLeast(session.level, 'strong')) {
			void climb('strong');
		}
	});
</script>

<svelte:head>
	<title>Console · Tunnel Weaver</title>
</svelte:head>

{#if atLeast(session.level, 'strong')}
	<Shell title={meta.title} subtitle={meta.subtitle} crumbs={meta.crumbs}>
		{@render children()}
	</Shell>
{:else}
	<Page labelledby="app-title">
		<h1 id="app-title">Your account</h1>
		<p class="lede" role="status">Checking your session…</p>
	</Page>
{/if}
