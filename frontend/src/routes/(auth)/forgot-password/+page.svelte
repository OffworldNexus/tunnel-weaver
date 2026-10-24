<script lang="ts">
	/**
	 * Requests a reset link. The relay answers identically whether or not the
	 * address has an account, so the acknowledgement never confirms existence.
	 */
	import Altcha from '#lib/account/Altcha.svelte';
	import { api } from '#lib/account/api';
	import EmailField from '#lib/account/EmailField.svelte';
	import { jsonForm } from '#lib/account/form';
	import { resetRequestSchema } from '#lib/account/schemas';
	import { stepUp } from '#lib/app/upgrade';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { resolve } from '$app/paths';

	let altcha = $state<{ reset(): void }>();
	let proof = $state('');
	let sent = $state(false);

	const sf = jsonForm(resetRequestSchema, { email: '' }, async (data) => {
		const res = await api('POST', '/api/account/reset/request', { ...data, altcha: proof }, stepUp);
		altcha?.reset();
		if (!res.ok) {
			return res.error ?? 'We could not send the reset link. Please try again.';
		}
		sent = true;
	});

	const { form, errors, message, submitting, enhance } = sf;
</script>

<svelte:head>
	<title>Reset your password · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="reset-request-title">
	{#if sent}
		<h1 id="reset-request-title">Reset request accepted</h1>
		<p class="lede">
			If an account exists, we'll email instructions to reset your password. Check your inbox and
			spam folder.
		</p>

		<div class="actions">
			<Keycap wide variant="ghost" href={resolve('/(auth)/sign-in')}>Back to sign in</Keycap>
		</div>
	{:else}
		<h1 id="reset-request-title">Reset your password</h1>
		<p class="lede">We'll email you a link to choose a new one.</p>

		<form class="form" method="POST" use:enhance novalidate>
			<EmailField bind:value={$form.email} error={$errors.email?.[0]} disabled={$submitting} />

			<Altcha purpose="reset" bind:this={altcha} bind:payload={proof} />

			{#if $message}
				<p class="notice-error" role="alert">{$message}</p>
			{/if}

			<Keycap type="submit" loading={$submitting} disabled={!proof || $submitting} wide>
				{$submitting ? 'Sending…' : 'Send reset link'}
			</Keycap>
		</form>

		<p class="switch"><a href={resolve('/(auth)/sign-in')}>Back to sign in</a></p>
	{/if}
</Page>
