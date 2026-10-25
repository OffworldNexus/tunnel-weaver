<script lang="ts">
	/**
	 * Sets the first password, reached from a verified email link. Submitting
	 * the completion token activates the account, or reports that the address
	 * already has one.
	 */
	import { api } from '#lib/account/api';
	import { jsonForm } from '#lib/account/form';
	import NewPassword from '#lib/account/NewPassword.svelte';
	import { setPasswordSchema } from '#lib/account/schemas';
	import { flow } from '#lib/account/state';
	import VerifiedEmail from '#lib/account/VerifiedEmail.svelte';
	import { climb } from '#lib/app/upgrade';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	const { completion_token, email = '' } = flow.load();

	const sf = jsonForm(setPasswordSchema, { password: '' }, async ({ password }) => {
		const res = await api<{ outcome: 'activated' | 'existing_account' }>(
			'POST',
			'/api/account/complete',
			{
				completion_token,
				password
			},
			climb
		);
		if (!res.ok || !res.data) {
			return res.error ?? 'We could not set your password. Please try again.';
		}
		if (res.data.outcome === 'activated') {
			flow.save({ notice: 'Your account is active. Sign in to continue.' });
			await goto(resolve('/(auth)/sign-in'));
		} else {
			await goto(resolve('/(auth)/existing-account'));
		}
	});

	const { form, errors, message, submitting, enhance } = sf;
</script>

<svelte:head>
	<title>Set your password · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="setpw-title">
	<h1 id="setpw-title">Set your password</h1>

	{#if completion_token}
		<p class="lede">Your email is verified. Secure your account.</p>

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
				{$submitting ? 'Saving…' : 'Save password'}
			</Keycap>
		</form>
	{:else}
		<p class="lede">This password setup link has expired. Start again to verify your email.</p>
		<div class="actions">
			<Keycap wide href={resolve('/(auth)/sign-up')}>Start again</Keycap>
		</div>
	{/if}

	<p class="switch"><a href={resolve('/(auth)/sign-in')}>Back to sign in</a></p>
</Page>
