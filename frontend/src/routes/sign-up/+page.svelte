<script lang="ts">
	/**
	 * Starts a registration. The reply carries a flow id (not a session) that
	 * the verification steps resume from.
	 */
	import Altcha from '#lib/account/Altcha.svelte';
	import { api } from '#lib/account/api';
	import EmailField from '#lib/account/EmailField.svelte';
	import { jsonForm } from '#lib/account/form';
	import { signUpSchema } from '#lib/account/schemas';
	import { flow } from '#lib/account/state';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	let altcha = $state<{ reset(): void }>();
	let proof = $state('');

	const sf = jsonForm(signUpSchema, { name: '', email: '' }, async (data) => {
		const res = await api<{ flow: string }>('/api/account/signup', { ...data, altcha: proof });
		altcha?.reset();
		if (!res.ok || !res.data) {
			return res.error ?? 'We could not start your signup. Please try again.';
		}
		flow.save({ flow: res.data.flow, email: data.email });
		await goto(resolve('/check-email'));
	});

	const { form, errors, message, submitting, enhance } = sf;
</script>

<svelte:head>
	<title>Create account · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="signup-title">
	<h1 id="signup-title">Create your account</h1>
	<p class="lede">A name and an email to get started.</p>

	<form class="form" method="POST" use:enhance novalidate>
		<div class="field">
			<label for="name">Name</label>
			<input
				id="name"
				name="name"
				type="text"
				autocomplete="name"
				placeholder="Your name"
				bind:value={$form.name}
				disabled={$submitting}
				aria-invalid={$errors.name ? 'true' : undefined}
			/>
			{#if $errors.name}<p class="field__error" aria-live="polite">{$errors.name[0]}</p>{/if}
		</div>

		<EmailField bind:value={$form.email} error={$errors.email?.[0]} disabled={$submitting} />

		<Altcha purpose="signup" bind:this={altcha} bind:payload={proof} />

		{#if $message}
			<p class="notice-error" role="alert">{$message}</p>
		{/if}

		<Keycap type="submit" loading={$submitting} disabled={!proof || $submitting} wide>
			{$submitting ? 'Creating…' : 'Continue with email'}
		</Keycap>
	</form>

	<p class="switch">Already have an account? <a href={resolve('/sign-in')}>Sign in</a></p>
</Page>
