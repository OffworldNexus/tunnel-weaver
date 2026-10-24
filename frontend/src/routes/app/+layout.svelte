<script lang="ts">
	/**
	 * The signed-in console layout: it mounts the shell for every `/app` route.
	 *
	 * It follows the session stream: the console needs `strong`, so whenever
	 * the level is lower — on arrival, or because a drop has just landed — the
	 * person is sent up the path the stream names (to sign-in once the session
	 * is gone). A drop announced ahead of time is told to the person first.
	 */
	import type { Snippet } from 'svelte';

	import { notify } from '#lib/account/notices';
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

	// Only a drop below what the console needs is worth a word: `certain`
	// ageing into `strong` takes nothing away from it.
	$effect(() => {
		const notice = session.notice;
		if (notice.at === 0 || atLeast(notice.to, 'strong')) {
			return;
		}
		notify(
			'error',
			notice.to === 'none'
				? `Your session ends in ${notice.in} seconds. Save your work and sign in again.`
				: `Your sign-in expires in ${notice.in} seconds; you will be asked for a new code.`
		);
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
