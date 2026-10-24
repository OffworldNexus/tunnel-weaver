<script lang="ts">
	/**
	 * The guard for every auth page: sign-in, sign-up, the recovery and
	 * verification steps, and the mid-signup holds.
	 *
	 * A visitor who already holds a session has no business here, so they are
	 * sent on — to the console, or on to `/pair` when a pairing detour is
	 * pending. The guard lives in the layout, not in each page, because gating
	 * here keeps it ahead of the page's own work: the children never mount, so
	 * `verify` and `reset` never spend their single-use link tokens on the way
	 * out. (The root layout has already settled the session, so this layout only
	 * ever runs with a known user or none.)
	 */
	import type { Snippet } from 'svelte';

	import { pairing } from '#lib/account/state';
	import { useSession } from '#lib/app/session.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	interface Props {
		children: Snippet;
	}

	let { children }: Props = $props();

	const session = useSession();

	$effect(() => {
		if (session.user) {
			void goto(resolve(pairing.load().detour ? '/pair' : '/app'), { replace: true });
		}
	});
</script>

{#if !session.user}
	{@render children()}
{/if}
