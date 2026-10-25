<script lang="ts">
	/**
	 * The guard for every auth page: sign-in, sign-up, the recovery and
	 * verification steps, the mid-signup holds, and the second-factor code step.
	 *
	 * A visitor who already holds a *finished* session has no business here, so
	 * they are sent on — to the console, or on to `/pair` when a pairing detour
	 * is pending. A visitor whose session is only `basic` (the password is proven
	 * but the emailed second factor is not) is sent to the code step instead:
	 * that one page is the only thing such a session may see, and every other
	 * auth page funnels into it.
	 *
	 * The guard lives in the layout, not in each page, because gating here keeps
	 * it ahead of the page's own work: the children never mount, so `verify` and
	 * `reset` never spend their single-use link tokens on the way out. (The root
	 * layout holds until the session stream's first frame, and the guard follows
	 * every later one.)
	 */
	import type { Snippet } from 'svelte';

	import { pairing } from '#lib/account/state';
	import { useSession } from '#lib/app/session.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';

	interface Props {
		children: Snippet;
	}

	let { children }: Props = $props();

	const session = useSession();
	const verifyCode = resolve('/(auth)/verify-code');

	/** Whether this page is allowed to render for the current session. */
	const visible = $derived(
		session.level === 'none' || (session.level === 'basic' && page.url.pathname === verifyCode)
	);

	$effect(() => {
		if (session.level === 'none') {
			return;
		}
		if (session.level === 'basic') {
			if (page.url.pathname !== verifyCode) {
				void goto(verifyCode, { replace: true });
			}
			return;
		}
		void goto(resolve(pairing.load().detour ? '/pair' : '/app'), { replace: true });
	});
</script>

{#if visible}
	{@render children()}
{/if}
