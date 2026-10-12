<script lang="ts">
	/**
	 * Forgot password (Figma "05 / Reset your password").
	 *
	 * One field: the address to send a reset link to. The relay answers
	 * identically whether or not the address has an account, so the accepted
	 * state never confirms existence — it only tells the user to check their
	 * inbox. Submission is gated behind a proof-of-work challenge.
	 */

	import { superForm } from 'sveltekit-superforms';
	import { valibot } from 'sveltekit-superforms/adapters';
	import { api, messageOf } from '#lib/account/api';
	import { resetRequestSchema } from '#lib/account/schemas';
	import { href } from '#lib/app/paths';
	import Altcha from '#lib/account/Altcha.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';

	let altchaPayload = '';
	let proofReset = 0;
	// Once the request is accepted, the form is replaced by the "check your
	// email" acknowledgement (the relay never confirms whether the account
	// exists).
	let sent = false;

	const sf = superForm(
		{ email: '' },
		{
			validators: valibot(resetRequestSchema),
			clearOnSubmit: 'errors-and-message',
			onSubmit: async ({ cancel }) => {
				cancel();
				const result = await sf.validateForm({ update: true });
				if (!result.valid || !altchaPayload) return;
				try {
					const res = await api<{ status: string }>('/api/account/reset/request', {
						method: 'POST',
						body: { email: result.data.email, altcha: altchaPayload }
					});
					if (res.ok) {
						sent = true;
						return;
					}
					sf.message.set(
						messageOf(res.data, 'We could not send the reset link. Please try again.')
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
			<Keycap wide variant="ghost" href={href('/sign-in')}>Back to sign in</Keycap>
		</div>
	{:else}
		<h1 id="reset-request-title">Reset your password</h1>
		<p class="lede">We'll email you a link to choose a new one.</p>

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

			<!-- Proof-of-work gate: the submit stays disabled until a proof is solved. -->
			<Altcha
				purpose="reset"
				resetSignal={proofReset}
				onSolved={(payload) => (altchaPayload = payload)}
				onExpired={() => (altchaPayload = '')}
			/>

			{#if $message}
				<p class="notice-error" role="alert" aria-live="assertive">{$message}</p>
			{/if}

			<Keycap type="submit" loading={$submitting} disabled={!altchaPayload || $submitting} wide>
				{$submitting ? 'Sending…' : 'Send reset link'}
			</Keycap>
		</form>

		<p class="switch"><a href={href('/sign-in')}>Back to sign in</a></p>
	{/if}
</Page>
