<script lang="ts">
	/**
	 * Create-account form.
	 *
	 * Collects a name and email, then starts a registration on the relay. The
	 * reply carries a flow id (not a session) that the later verification steps
	 * resume from, kept in session state so a mid-flow refresh doesn't lose it.
	 * Submission is gated behind a proof-of-work challenge.
	 */

	import { goto } from '$app/navigation';
	import { superForm } from 'sveltekit-superforms';
	import { valibot } from 'sveltekit-superforms/adapters';
	import { api, messageOf } from '#lib/api';
	import { saveFlow } from '#lib/flow';
	import { href } from '#lib/paths';
	import { signUpSchema } from '#lib/schemas';
	import Altcha from '#lib/Altcha.svelte';
	import Brand from '#lib/Brand.svelte';
	import Keycap from '#lib/Keycap.svelte';
	import SiteFooter from '#lib/SiteFooter.svelte';

	let altchaPayload = '';
	let proofReset = 0;

	// Start the registration; the returned flow id drives the verification steps
	// that follow.
	const sf = superForm(
		{ name: '', email: '' },
		{
			validators: valibot(signUpSchema),
			clearOnSubmit: 'errors-and-message',
			onSubmit: async ({ cancel }) => {
				cancel();
				const result = await sf.validateForm({ update: true });
				if (!result.valid || !altchaPayload) return;
				try {
					const res = await api<{ status: string; flow: string }>('/api/account/signup', {
						method: 'POST',
						body: {
							name: result.data.name,
							email: result.data.email,
							altcha: altchaPayload
						}
					});
					if (res.ok && res.data?.flow) {
						saveFlow({ flow: res.data.flow, email: result.data.email, name: result.data.name });
						await goto(href('/check-email'));
						return;
					}
					sf.message.set(messageOf(res.data, 'We could not start your signup. Please try again.'));
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
	<title>Create account · Tunnel Weaver</title>
</svelte:head>

<div class="page">
	<Brand center />
	<main id="main" class="column" aria-labelledby="signup-title">
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
				purpose="signup"
				resetSignal={proofReset}
				onSolved={(payload) => (altchaPayload = payload)}
				onExpired={() => (altchaPayload = '')}
			/>

			{#if $message}
				<p class="notice-error" role="alert" aria-live="assertive">{$message}</p>
			{/if}

			<Keycap type="submit" loading={$submitting} disabled={!altchaPayload || $submitting} wide>
				{$submitting ? 'Creating…' : 'Continue with email'}
			</Keycap>
		</form>

		<p class="switch">Already have an account? <a href={href('/sign-in')}>Sign in</a></p>
	</main>
	<SiteFooter />
</div>
