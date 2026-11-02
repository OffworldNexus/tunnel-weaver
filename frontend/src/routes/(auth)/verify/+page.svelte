<script lang="ts">
	/**
	 * The signup verification step: enter the six-digit code the relay emailed.
	 * The pending flow id lives in session state, not the URL, so a shared
	 * screen cannot resume someone else's signup.
	 *
	 * The code proves ownership of the address; a new one goes on to set a
	 * password, while an address that already has an account is only disclosed
	 * now that ownership is proven.
	 */
	import { api } from '#lib/account/api';
	import CodeEntry from '#lib/account/CodeEntry.svelte';
	import { useCooldown } from '#lib/account/cooldown.svelte';
	import { flow } from '#lib/account/state';
	import { climb } from '#lib/app/upgrade';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	type VerifyOutcome =
		| { outcome: 'set_password'; completion_token: string; email: string }
		| { outcome: 'existing_account'; email: string };

	const carried = flow.load();
	const cooldown = useCooldown();

	let status = $state('');
	let resending = $state(false);

	// A code was emailed on the way here.
	if (carried.flow) {
		void cooldown.start();
	}

	async function submit(code: string): Promise<string | void> {
		const res = await api<VerifyOutcome>(
			'POST',
			'/api/account/verify',
			{ flow: carried.flow, code },
			climb
		);
		if (!res.ok || !res.data) {
			return res.error ?? 'That code was not accepted. Request a new one.';
		}
		if (res.data.outcome === 'set_password') {
			flow.save({ completion_token: res.data.completion_token, email: res.data.email });
			await goto(resolve('/(auth)/set-password'));
		} else {
			flow.save({ email: res.data.email });
			await goto(resolve('/(auth)/existing-account'));
		}
	}

	async function resend(): Promise<void> {
		resending = true;
		status = '';
		const res = await api<{ status: string }>(
			'POST',
			'/api/account/resend',
			{ flow: carried.flow },
			climb
		);
		resending = false;
		if (!res.ok) {
			status = res.error ?? 'We could not send a new code. Try again.';
			return;
		}
		status =
			res.data?.status === 'cooldown'
				? 'A code was just sent. Enter the last one you received.'
				: 'A new code is on its way.';
		await cooldown.start();
	}

	function useAnotherEmail(): void {
		flow.clear();
		void goto(resolve('/(auth)/sign-up'));
	}
</script>

<svelte:head>
	<title>Enter your code · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="verify-title">
	{#if carried.flow}
		<h1 id="verify-title">Enter your code</h1>
		<CodeEntry icon="inbox" source="Email" {submit} {status}>
			{#snippet detail()}
				We emailed a six-digit code to <strong>{carried.email || 'your address'}</strong>.
			{/snippet}
			{#snippet actions()}
				<Keycap
					type="button"
					variant="ghost"
					onclick={resend}
					loading={resending}
					disabled={cooldown.remaining > 0}
				>
					{cooldown.remaining > 0 ? `Send a new code in ${cooldown.remaining}s` : 'Send a new code'}
				</Keycap>
				<Keycap type="button" variant="ghost" onclick={useAnotherEmail}>
					Use a different email
				</Keycap>
			{/snippet}
		</CodeEntry>
	{:else}
		<h1 id="verify-title">Nothing to verify</h1>
		<p class="lede">This page needs a signup in progress. Start one to get a code.</p>
		<div class="actions">
			<Keycap wide href={resolve('/(auth)/sign-up')}>Create an account</Keycap>
		</div>
	{/if}

	<p class="switch"><a href={resolve('/(auth)/sign-in')}>Back to sign in</a></p>
</Page>
