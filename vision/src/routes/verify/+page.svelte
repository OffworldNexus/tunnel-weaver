<script lang="ts">
	/**
	 * Exchanges the single-use email-link token for the next step: a new address
	 * goes on to set a password; an address that already has an account is only
	 * disclosed now that ownership is proven. Either way the link is spent, so a
	 * failure is terminal.
	 */
	import { onMount } from 'svelte';

	import { api } from '#lib/account/api';
	import { flow } from '#lib/account/state';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';

	type VerifyOutcome =
		| { outcome: 'set_password'; completion_token: string; email: string }
		| { outcome: 'existing_account'; email: string };

	let message = '';
	const canResend = Boolean(flow.load().flow);

	onMount(async () => {
		const token = page.url.searchParams.get('token');
		if (!token) {
			message = 'This link is missing its token.';
			return;
		}
		const res = await api<VerifyOutcome>('/api/account/verify', { token });
		if (!res.ok || !res.data) {
			message = res.error ?? 'This link has expired or has already been used.';
			return;
		}
		if (res.data.outcome === 'set_password') {
			flow.save({ completion_token: res.data.completion_token, email: res.data.email });
			await goto(resolve('/set-password'));
		} else {
			flow.save({ email: res.data.email });
			await goto(resolve('/existing-account'));
		}
	});
</script>

<svelte:head>
	<title>Verify email · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="verify-title">
	{#if !message}
		<h1 id="verify-title">Verifying your link</h1>
		<p class="lede" aria-live="polite">One moment while we confirm your email address…</p>
	{:else}
		<h1 id="verify-title">This link no longer works</h1>
		<p class="lede">{message}</p>
		<div class="actions">
			{#if canResend}
				<Keycap wide href={resolve('/check-email')}>Request a new link</Keycap>
			{/if}
			<Keycap wide variant="ghost" href={resolve('/sign-up')}>Start again</Keycap>
		</div>
	{/if}

	<p class="switch"><a href={resolve('/sign-in')}>Back to sign in</a></p>
</Page>
