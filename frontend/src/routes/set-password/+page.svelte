<script lang="ts">
	/**
	 * Set-password step, reached from a verified email link.
	 *
	 * Holds the completion token carried through the flow; submitting it
	 * activates the account (or reports that the address already has one). The
	 * minimum length is mirrored from the relay for guidance, but the relay
	 * enforces the real one on submit.
	 */

	import { goto } from '$app/navigation';
	import { superForm } from 'sveltekit-superforms';
	import { valibot } from 'sveltekit-superforms/adapters';
	import { api, messageOf } from '#lib/account/api';
	import { ensureConfig } from '#lib/account/config';
	import { loadFlow, saveFlow } from '#lib/account/flow';
	import { setPasswordSchema } from '#lib/account/schemas';
	import { href } from '#lib/app/paths';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';

	const carried = loadFlow();
	const completionToken = carried.completion_token ?? '';
	const email = carried.email ?? '';

	// The relay owns the minimum; the client mirrors it for guidance.
	const limits = { min: 8 };
	let minLength = limits.min;
	let showPassword = false;

	ensureConfig()
		.then((cfg) => {
			limits.min = cfg.min_password_length;
			minLength = cfg.min_password_length;
		})
		.catch(() => {
			// The relay still enforces the true minimum on submit.
		});

	const sf = superForm(
		{ password: '' },
		{
			validators: valibot(setPasswordSchema(() => limits.min)),
			clearOnSubmit: 'errors-and-message',
			onSubmit: async ({ cancel }) => {
				cancel();
				const result = await sf.validateForm({ update: true });
				if (!result.valid) return;
				try {
					const res = await api<{ outcome: 'activated' | 'existing_account'; email?: string }>(
						'/api/account/complete',
						{
							method: 'POST',
							body: { completion_token: completionToken, password: result.data.password }
						}
					);
					// Activated: the account now exists — send them to sign in.
					if (res.ok && res.data?.outcome === 'activated') {
						saveFlow({
							notice: 'Your account is active. Sign in to continue.',
							noticeKind: 'success',
							email
						});
						await goto(href('/sign-in'));
						return;
					}
					// The address turned out to already have an account.
					if (res.ok && res.data?.outcome === 'existing_account') {
						saveFlow({ email: res.data.email ?? email });
						await goto(href('/existing-account'));
						return;
					}
					sf.message.set(
						messageOf(res.data, 'We could not set your password. Please try again.')
					);
				} catch {
					sf.message.set('We could not reach the server. Check your connection and try again.');
				}
			}
		}
	);

	const { form, errors, message, submitting, enhance } = sf;

	// A rough strength hint for the UI only; the relay keeps the real policy.
	$: strength = strengthOf($form.password);

	function strengthOf(value: string): { level: 'weak' | 'fair' | 'strong'; pct: number; label: string } {
		let score = 0;
		if (value.length >= 8) score++;
		if (value.length >= 12) score++;
		if (/[a-z]/.test(value) && /[A-Z]/.test(value)) score++;
		if (/\d/.test(value)) score++;
		if (/[^A-Za-z0-9]/.test(value)) score++;

		if (value.length === 0) return { level: 'weak', pct: 0, label: '' };
		if (score <= 2) return { level: 'weak', pct: 33, label: 'Weak' };
		if (score === 3) return { level: 'fair', pct: 66, label: 'Fair' };
		return { level: 'strong', pct: 100, label: 'Strong' };
	}
</script>

<svelte:head>
	<title>Set your password · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="setpw-title">
	<h1 id="setpw-title">Set your password</h1>

	{#if completionToken}
		<p class="lede">Your email is verified. Secure your account.</p>

		<form class="form" method="POST" use:enhance novalidate>
			<!-- A real username control (readonly) so password managers can
			     associate the new password with the verified address. -->
			<div class="field">
				<label for="username">Email</label>
				<input
					id="username"
					name="username"
					type="email"
					autocomplete="username"
					readonly
					value={email}
				/>
				<p class="hint"><span class="check" aria-hidden="true">✓</span> Verified email</p>
			</div>

			<div class="field">
				<label for="password">New password</label>
				<div class="field__row">
					<input
						id="password"
						name="password"
						type={showPassword ? 'text' : 'password'}
						autocomplete="new-password"
						placeholder="Create a unique password"
						bind:value={$form.password}
						disabled={$submitting}
						aria-invalid={$errors.password ? 'true' : undefined}
						aria-describedby="password-hint"
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

				<div class="strength" aria-hidden="true">
					<span class="strength__track">
						<span class="strength__fill" data-level={strength.level} style={`width:${strength.pct}%`}></span>
					</span>
					<span class="strength__label">{strength.label}</span>
				</div>

				{#if $errors.password}
					<p class="field__error" aria-live="polite">{$errors.password[0]}</p>
				{/if}

				<p id="password-hint" class="hint">
					Use at least {minLength} characters. A longer, unique passphrase beats a short,
					complicated one.
				</p>
			</div>

			{#if $message}
				<p class="notice-error" role="alert" aria-live="assertive">{$message}</p>
			{/if}

			<Keycap type="submit" loading={$submitting} disabled={$submitting} wide>
				{$submitting ? 'Saving…' : 'Save password'}
			</Keycap>
		</form>
	{:else}
		<p class="lede">This password setup link has expired. Start again to verify your email.</p>
		<div class="actions">
			<Keycap wide href={href('/sign-up')}>Start again</Keycap>
		</div>
	{/if}

	<p class="switch"><a href={href('/sign-in')}>Back to sign in</a></p>
</Page>

<style lang="scss">
	/* The check mark on the verified address. */
	.check {
		color: var(--tw-success);
		font-weight: 700;
	}

	/* Password strength meter (guidance only). */
	.strength {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.strength__track {
		flex: 1;
		height: 6px;
		border-radius: 999px;
		background: var(--tw-well);
		border: 1.5px solid var(--tw-border);
		overflow: hidden;
	}

	.strength__fill {
		display: block;
		height: 100%;
		background: var(--tw-success);
		transition: width 140ms ease;
	}

	.strength__fill[data-level='weak'] {
		background: var(--tw-danger);
	}

	.strength__label {
		min-width: 3.6rem;
		text-align: right;
		color: var(--tw-muted);
		font-size: 14px;
	}

	@media (prefers-reduced-motion: reduce) {
		.strength__fill {
			transition: none;
		}
	}
</style>
