<script lang="ts">
	/**
	 * Chooses a new password from the emailed reset link.
	 *
	 * The token rides in the URL fragment (`/reset#token=…`), which never reaches
	 * the server or its logs. On mount it is read, stripped from the address bar,
	 * and checked (without being spent) for the account's address.
	 *
	 * This is a one-shot mutation, not a load: the reset token is single-use, so
	 * it stays an explicit one-shot effect rather than a route loader — a loader
	 * could re-run and would have to answer again about a token that is already
	 * spent. `untrack` keeps it from ever re-running.
	 */
	import { untrack } from 'svelte';

	import { api } from '#lib/account/api';
	import { jsonForm } from '#lib/account/form';
	import NewPassword from '#lib/account/NewPassword.svelte';
	import { setPasswordSchema } from '#lib/account/schemas';
	import { flow } from '#lib/account/state';
	import VerifiedEmail from '#lib/account/VerifiedEmail.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	let phase = $state<'checking' | 'form' | 'invalid'>('checking');
	let token = $state('');
	let email = $state('');

	async function run() {
		token = new URLSearchParams(location.hash.slice(1)).get('token') ?? '';
		if (!token) {
			phase = 'invalid';
			return;
		}
		void goto(resolve('/reset'), { replace: true, shallow: true });
		const res = await api<{ valid: boolean; email?: string }>('/api/account/reset/check', {
			token
		});
		if (res.data?.valid && res.data.email) {
			email = res.data.email;
			phase = 'form';
		} else {
			phase = 'invalid';
		}
	}

	$effect(() => {
		untrack(() => {
			void run();
		});
	});

	const sf = jsonForm(setPasswordSchema, { password: '' }, async ({ password }) => {
		const res = await api('/api/account/reset/complete', { token, password });
		if (!res.ok) {
			return res.error ?? 'We could not reset your password. Request a new link and try again.';
		}
		flow.save({ notice: 'Your password has been reset. Sign in with your new password.', email });
		await goto(resolve('/sign-in'));
	});

	const { form, errors, message, submitting, enhance } = sf;
</script>

<svelte:head>
	<title>Choose a new password · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="reset-title">
	{#if phase === 'checking'}
		<h1 id="reset-title">Choose a new password</h1>
		<p class="lede" role="status">Checking your reset link…</p>
	{:else if phase === 'form'}
		<h1 id="reset-title">Choose a new password</h1>
		<p class="lede">Use a unique password for Tunnel Weaver.</p>

		<form class="form" method="POST" use:enhance novalidate>
			<VerifiedEmail {email} />

			<NewPassword
				id="password"
				bind:value={$form.password}
				error={$errors.password?.[0]}
				disabled={$submitting}
			/>

			{#if $message}
				<p class="notice-error" role="alert">{$message}</p>
			{/if}

			<Keycap type="submit" loading={$submitting} disabled={$submitting} wide>
				{$submitting ? 'Resetting…' : 'Reset password'}
			</Keycap>
		</form>

		<p class="switch"><a href={resolve('/sign-in')}>Back to sign in</a></p>
	{:else}
		<h1 id="reset-title">Link expired or used</h1>
		<p class="lede">This link is no longer available. Request a fresh one to continue.</p>

		<div class="actions">
			<Keycap wide variant="ghost" href={resolve('/forgot-password')}>Request a new link</Keycap>
		</div>

		<p class="switch"><a href={resolve('/sign-in')}>Back to sign in</a></p>
	{/if}
</Page>
