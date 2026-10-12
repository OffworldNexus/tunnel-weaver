<script lang="ts">
	/**
	 * Email-link verification.
	 *
	 * Runs once on mount: exchanges the single-use token from the URL for the
	 * next step. A new address yields a completion token (→ set a password); an
	 * address that already has an account is only disclosed now. Either way the
	 * link is consumed, so failures are terminal and offer a resend.
	 */

	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { api, messageOf } from '#lib/account/api';
	import { loadFlow, saveFlow } from '#lib/account/flow';
	import { networkError } from '#lib/account/notices';
	import { href } from '#lib/app/paths';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';

	type VerifyOutcome =
		| { outcome: 'set_password'; completion_token: string; name: string; email: string }
		| { outcome: 'existing_account'; email: string };

	let status: 'checking' | 'expired' = 'checking';
	let message = '';
	const carried = loadFlow();
	const canResend = Boolean(carried.flow);

	onMount(() => {
		run();
	});

	// Exchange the single-use link token; both outcomes consume it.
	async function run() {
		status = 'checking';
		message = '';
		const token = page.url.searchParams.get('token') ?? '';
		if (!token) {
			status = 'expired';
			message = 'This link is missing its token.';
			return;
		}
		try {
			const result = await api<VerifyOutcome>('/api/account/verify', {
				method: 'POST',
				body: { token }
			});
			if (result.ok && result.data?.outcome === 'set_password') {
				// New address: keep the completion token for the password step.
				saveFlow({
					completion_token: result.data.completion_token,
					name: result.data.name,
					email: result.data.email
				});
				await goto(href('/set-password'));
				return;
			}
			if (result.ok && result.data?.outcome === 'existing_account') {
				// Already registered: reveal it only now that ownership is proven.
				saveFlow({ email: result.data.email });
				await goto(href('/existing-account'));
				return;
			}
			status = 'expired';
			message = messageOf(result.data, 'This link has expired or has already been used.');
		} catch {
			status = 'expired';
			message = 'We could not reach the server. Please try again.';
			networkError();
		}
	}
</script>

<svelte:head>
	<title>Verify email · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="verify-title">
	<h1 id="verify-title">
		{status === 'checking' ? 'Verifying your link' : 'This link no longer works'}
	</h1>

	{#if status === 'checking'}
		<p class="lede" aria-live="polite">One moment while we confirm your email address…</p>
	{:else}
		<p class="lede">{message}</p>
		<div class="actions" style="margin-top:24px">
			{#if canResend}
				<Keycap wide href={href('/check-email')}>Request a new link</Keycap>
			{/if}
			<Keycap wide variant="ghost" href={href('/sign-up')}>Start again</Keycap>
		</div>
	{/if}

	<p class="switch"><a href={href('/sign-in')}>Back to sign in</a></p>
</Page>
