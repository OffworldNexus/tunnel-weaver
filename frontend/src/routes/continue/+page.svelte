<script lang="ts">
	/**
	 * Signs the owner in from the inactivity-warning email (WVR-160).
	 *
	 * The token rides in the URL fragment (`/continue#token=…`), which never
	 * reaches the server or its logs; on mount it is read, stripped from the
	 * address bar, and posted to the relay. The link is single-use, so this is a
	 * one-shot effect rather than a load: a loader could re-run and would have to
	 * answer again about a token that is already spent. `untrack` keeps it from
	 * ever re-running.
	 */
	import { untrack } from 'svelte';

	import { api } from '#lib/account/api';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	let phase = $state<'working' | 'invalid'>('working');

	async function run() {
		const token = new URLSearchParams(location.hash.slice(1)).get('token') ?? '';
		if (!token) {
			phase = 'invalid';
			return;
		}
		void goto(resolve('/continue'), { replace: true, shallow: true });
		const res = await api('/api/account/continue', { token });
		if (res.ok) {
			await goto(resolve('/app'));
		} else {
			phase = 'invalid';
		}
	}

	$effect(() => {
		untrack(() => {
			void run();
		});
	});
</script>

<svelte:head>
	<title>Signing you in · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="continue-title">
	{#if phase === 'working'}
		<h1 id="continue-title">Signing you in</h1>
		<p class="lede" role="status">One moment while we sign you in…</p>
	{:else}
		<h1 id="continue-title">This link has expired</h1>
		<p class="lede">
			This sign-in link is no longer available. Sign in as usual to keep your account.
		</p>

		<div class="actions">
			<Keycap wide href={resolve('/sign-in')}>Go to sign in</Keycap>
		</div>
	{/if}
</Page>
