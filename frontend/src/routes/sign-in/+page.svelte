<script lang="ts">
	/**
	 * Sign-in form.
	 *
	 * Email + password behind a proof-of-work challenge; on success the relay
	 * sets the session cookie and we land on the signed-in shell.
	 */

	import { goto } from '$app/navigation';
	import { superForm } from 'sveltekit-superforms';
	import { valibot } from 'sveltekit-superforms/adapters';
	import { api, messageOf } from '#lib/account/api';
	import { clearFlow, loadFlow, saveFlow } from '#lib/account/flow';
	import { notify } from '#lib/account/notices';
	import { signInSchema } from '#lib/account/schemas';
	import { href } from '#lib/app/paths';
	import Altcha from '#lib/account/Altcha.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';

	const carried = loadFlow();
	if (carried.notice) {
		notify(carried.noticeKind ?? 'success', carried.notice);
		// Consume the notice so it is not re-announced on a later visit.
		saveFlow({ notice: undefined, noticeKind: undefined });
	}

	let altchaPayload = '';
	let proofReset = 0;
	let showPassword = false;

	const sf = superForm(
		{ email: carried.email ?? '', password: '' },
		{
			validators: valibot(signInSchema),
			clearOnSubmit: 'errors-and-message',
			onSubmit: async ({ cancel }) => {
				// We own the submission: cancel Superforms' own form post and
				// call the same-origin JSON API instead.
				cancel();
				const result = await sf.validateForm({ update: true });
				if (!result.valid || !altchaPayload) return;
				try {
					const res = await api<{ ok: boolean; name: string }>('/api/account/login', {
						method: 'POST',
						body: {
							email: result.data.email,
							password: result.data.password,
							altcha: altchaPayload
						}
					});
					if (res.ok && res.data?.ok) {
						clearFlow();
						await goto(href('/app'));
						return;
					}
					sf.message.set(
						messageOf(
							res.data,
							'That email and password did not match. Please check and try again.'
						)
					);
				} catch {
					sf.message.set('We could not reach the server. Check your connection and try again.');
				} finally {
					resetProof();
				}
			}
		}
	);

	const { form, errors, message, submitting, enhance } = sf;

	// A proof is single-use: after any attempt (success or failure) the widget
	// must solve a fresh one before the next submit.
	function resetProof() {
		altchaPayload = '';
		proofReset += 1;
	}
</script>

<svelte:head>
	<title>Sign in · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="signin-title">
	<h1 id="signin-title">Sign in</h1>
	<p class="lede">Your tunnels, devices and account.</p>

	<form class="form" method="POST" use:enhance novalidate>
		<div class="field">
			<label for="email">Email</label>
			<input
				id="email"
				name="email"
				type="email"
				autocomplete="username"
				inputmode="email"
				autocapitalize="none"
				spellcheck="false"
				placeholder="you@example.com"
				bind:value={$form.email}
				disabled={$submitting}
				aria-invalid={$errors.email ? 'true' : undefined}
			/>
			{#if $errors.email}<p class="field__error" aria-live="polite">{$errors.email[0]}</p>{/if}
		</div>

		<div class="field">
			<label for="password">Password</label>
			<div class="field__row">
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
					on:click={() => (showPassword = !showPassword)}
				>
					{showPassword ? 'Hide password' : 'Show password'}
				</button>
			</div>
			{#if $errors.password}<p class="field__error" aria-live="polite">{$errors.password[0]}</p>{/if}
		</div>

		<p class="forgot"><a href={href('/forgot-password')}>Forgot password?</a></p>

		<!-- Proof-of-work gate: the submit stays disabled until a proof is solved. -->
		<Altcha
			purpose="login"
			resetSignal={proofReset}
			onSolved={(payload) => (altchaPayload = payload)}
			onExpired={() => (altchaPayload = '')}
		/>

		{#if $message}
			<p class="notice-error" role="alert" aria-live="assertive">{$message}</p>
		{/if}

		<Keycap type="submit" loading={$submitting} disabled={!altchaPayload || $submitting} wide>
			{$submitting ? 'Signing in…' : 'Sign in'}
		</Keycap>
	</form>

	<p class="switch"><a href={href('/sign-up')}>Create an account</a></p>
</Page>
