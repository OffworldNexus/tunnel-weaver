<script lang="ts">
	/**
	 * The guard for every auth page: sign-in, sign-up, the recovery and
	 * verification steps, the mid-signup holds, and the second-factor code step.
	 *
	 * A visitor who already holds a *finished* session has no business here, so
	 * they are sent on — to the console, or on to `/pair` when a pairing detour
	 * is pending. A visitor whose session is only `basic` (the password is proven
	 * but the second factor is not) is sent to the code step instead: that step
	 * and the chooser it hands off to are the only things such a session may see,
	 * and every other auth page funnels into the code step.
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
	/**
	 * The pages a `basic` session — the password proven, the second factor not —
	 * may see: the code step, and the chooser it hands off to. Those two are the
	 * whole of what such a session can do, and every other auth page funnels into
	 * the code step.
	 */
	const basicPages: string[] = [verifyCode, resolve('/(auth)/another-way')];

	/** Whether this page is allowed to render for the current session. */
	const visible = $derived(
		session.level === 'none' ||
			(session.level === 'basic' && basicPages.includes(page.url.pathname))
	);

	$effect(() => {
		if (session.level === 'none') {
			return;
		}
		if (session.level === 'basic') {
			if (!basicPages.includes(page.url.pathname)) {
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
