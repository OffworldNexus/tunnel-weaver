<script lang="ts">
	import Altcha from '#lib/account/Altcha.svelte';
	import { api } from '#lib/account/api';
	import EmailField from '#lib/account/EmailField.svelte';
	import { jsonForm } from '#lib/account/form';
	import { notify } from '#lib/account/notices';
	import { signInSchema } from '#lib/account/schemas';
	import { flow, pairing } from '#lib/account/state';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	const carried = flow.load();
	if (carried.notice) {
		notify('success', carried.notice);
		flow.save({ notice: undefined });
	}

	let altcha: { reset(): void };
	let proof = '';
	let showPassword = false;

	const sf = jsonForm(signInSchema, { email: carried.email ?? '', password: '' }, async (data) => {
		const res = await api('/api/account/login', { ...data, altcha: proof });
		altcha.reset();
		if (!res.ok) {
			return res.error ?? 'That email and password did not match.';
		}
		flow.clear();
		// A pairing detour sent the person here: return to its confirmation.
		await goto(resolve(pairing.load().detour ? '/pair' : '/app'));
	});

	const { form, errors, message, submitting, enhance } = sf;
</script>

<svelte:head>
	<title>Sign in · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="signin-title">
	<h1 id="signin-title">Sign in</h1>
	<p class="lede">Your tunnels, devices and account.</p>

	<form class="form" method="POST" use:enhance novalidate>
		<EmailField bind:value={$form.email} error={$errors.email?.[0]} disabled={$submitting} />

		<div class="field">
			<label for="password">Password</label>
			<input
				id="password"
				name="password"
				type={showPassword ? 'text' : 'password'}
				autocomplete="current-password"
				placeholder="Your password"
				bind:value={$form.password}
				disabled={$submitting}
				aria-invalid={$errors.password ? 'true' : undefined}
			/>
			<button
				type="button"
				class="toggle"
				aria-pressed={showPassword}
				onclick={() => (showPassword = !showPassword)}
			>
				{showPassword ? 'Hide password' : 'Show password'}
			</button>
			{#if $errors.password}<p class="field__error" aria-live="polite">
					{$errors.password[0]}
				</p>{/if}
		</div>

		<p><a href={resolve('/forgot-password')}>Forgot password?</a></p>

		<Altcha purpose="login" bind:this={altcha} bind:payload={proof} />

		{#if $message}
			<p class="notice-error" role="alert">{$message}</p>
		{/if}

		<Keycap type="submit" loading={$submitting} disabled={!proof || $submitting} wide>
			{$submitting ? 'Signing in…' : 'Sign in'}
		</Keycap>
	</form>

	<p class="switch"><a href={resolve('/sign-up')}>Create an account</a></p>
</Page>
