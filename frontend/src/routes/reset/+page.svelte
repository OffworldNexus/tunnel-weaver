<script lang="ts">
	/**
	 * Choose a new password (Figma "06 / Choose a new password"), reached from
	 * the emailed reset link.
	 *
	 * The reset token rides in the URL *fragment* (`/reset#token=…`), which is
	 * never sent to the server — so it cannot leak through HTTP access logs. On
	 * mount it is read, stripped from the address bar, and exchanged (without
	 * being consumed) for the verified address via `reset/check`. A dead or
	 * already-used link renders the recoverable "Link expired or used" state.
	 */

	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { superForm } from 'sveltekit-superforms';
	import { valibot } from 'sveltekit-superforms/adapters';
	import { api, messageOf } from '#lib/account/api';
	import { ensureConfig } from '#lib/account/config';
	import { saveFlow } from '#lib/account/flow';
	import { setPasswordSchema } from '#lib/account/schemas';
	import PasswordStrength from '#lib/account/PasswordStrength.svelte';
	import { href } from '#lib/app/paths';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';

	let phase: 'checking' | 'form' | 'invalid' = 'checking';
	let token = '';
	let email = '';
	let showPassword = false;

	// The relay owns the minimum; the client mirrors it for guidance.
	const limits = { min: 8 };
	let minLength = limits.min;

	ensureConfig()
		.then((cfg) => {
			limits.min = cfg.min_password_length;
			minLength = cfg.min_password_length;
		})
		.catch(() => {
			// The relay still enforces the true minimum on submit.
		});

	/** Reads the raw token out of the URL fragment (never the query string). */
	function readToken(): string {
		if (typeof window === 'undefined') return '';
		const hash = window.location.hash.replace(/^#/, '');
		return new URLSearchParams(hash).get('token') ?? '';
	}

	onMount(async () => {
		const raw = readToken();
		if (!raw) {
			phase = 'invalid';
			return;
		}
		token = raw;
		// Drop the secret from the address bar and history. It was never sent to
		// the server, and the token is resolved through the request body instead.
		void goto(href('/reset'), { replace: true, shallow: true });
		try {
			const res = await api<{ valid: boolean; email?: string }>('/api/account/reset/check', {
				method: 'POST',
				body: { token }
			});
			if (res.ok && res.data?.valid) {
				email = res.data.email ?? '';
				phase = 'form';
				return;
			}
		} catch {
			// Fall through: an unreachable relay is treated as a dead link, which
			// is recoverable via "Request a new link".
		}
		phase = 'invalid';
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
					const res = await api<{ outcome: string }>('/api/account/reset/complete', {
						method: 'POST',
						body: { token, password: result.data.password }
					});
					if (res.ok && res.data?.outcome === 'reset') {
						saveFlow({
							notice: 'Your password has been reset. Sign in with your new password.',
							noticeKind: 'success',
							email
						});
						await goto(href('/sign-in'));
						return;
					}
					sf.message.set(
						messageOf(
							res.data,
							'We could not reset your password. Request a new link and try again.'
						)
					);
				} catch {
					sf.message.set('We could not reach the server. Check your connection and try again.');
				}
			}
		}
	);

	const { form, errors, message, submitting, enhance } = sf;
</script>

<svelte:head>
	<title>Choose a new password · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="reset-title">
	{#if phase === 'checking'}
		<h1 id="reset-title">Choose a new password</h1>
		<p class="lede" role="status" aria-live="polite">Checking your reset link…</p>
	{:else if phase === 'form'}
		<h1 id="reset-title">Choose a new password</h1>
		<p class="lede">Use a unique password for Tunnel Weaver.</p>

		<form class="form" method="POST" use:enhance novalidate>
			<!-- The verified address, drawn as Figma's single chip. The control
			     inside is a real readonly `autocomplete="username"` input so
			     password managers still associate the account; it is styled
			     borderless so the box reads as one chip. -->
			<div class="chip">
				<span class="chip__check" aria-hidden="true">✓</span>
				<input
					id="username"
					name="username"
					class="chip__input"
					type="email"
					autocomplete="username"
					aria-label="Email"
					readonly
					value={email}
				/>
			</div>

			<div class="field">
				<label for="password">New password</label>
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

				<PasswordStrength value={$form.password} />

				{#if $errors.password}
					<p class="field__error" aria-live="polite">{$errors.password[0]}</p>
				{/if}

				<p id="password-hint" class="hint">
					Use a long, unique password — at least {minLength} characters. Password-manager
					suggestions are welcome.
				</p>

				<!-- Figma puts the show/hide link below the helper. -->
				<button
					type="button"
					class="toggle"
					aria-pressed={showPassword}
					on:click={() => (showPassword = !showPassword)}
				>
					{showPassword ? 'Hide password' : 'Show password'}
				</button>
			</div>

			{#if $message}
				<p class="notice-error" role="alert" aria-live="assertive">{$message}</p>
			{/if}

			<Keycap type="submit" loading={$submitting} disabled={$submitting} wide>
				{$submitting ? 'Resetting…' : 'Reset password'}
			</Keycap>
		</form>

		<p class="note">
			After resetting, sign in normally. Your second factor is still required if enabled.
		</p>

		<p class="switch"><a href={href('/sign-in')}>Back to sign in</a></p>
	{:else}
		<h1 id="reset-title">Link expired or used</h1>
		<p class="lede">This link is no longer available. Request a fresh one to continue.</p>

		<div class="actions">
			<Keycap wide variant="ghost" href={href('/forgot-password')}>Request a new link</Keycap>
		</div>

		<p class="switch"><a href={href('/sign-in')}>Back to sign in</a></p>
	{/if}
</Page>

<style lang="scss">
	/* The verified-address chip: one bordered box holding the check and the
	   address, as Figma draws it. The real username input inside is borderless
	   so password managers still see a control. */
	.chip {
		display: flex;
		align-items: center;
		gap: 8px;
		min-height: 44px;
		padding: 0 14px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
	}

	.chip__check {
		color: var(--tw-success);
		font-weight: 700;
	}

	.chip__input {
		flex: 1;
		min-width: 0;
		border: 0;
		padding: 0;
		background: none;
		color: var(--tw-muted);
		font: 400 16px/1 var(--tw-sans);
		/* A long address cannot wrap inside a single-line control, so signpost
		   the truncation instead of hard-clipping it. */
		text-overflow: ellipsis;
	}

	/* The second-factor note under the form. */
	.note {
		margin-top: 16px;
		color: var(--tw-muted);
		font-size: 16px;
		line-height: 1.5;
	}

	/* Figma "Form / new" renders the helper ("Field / 416 / Helper") at
	   16px/1.4, not the 14px shared `.hint`. The verified address sits in the
	   file's 16px/1.5 "Notice" chip. */
	.hint {
		font-size: 16px;
		line-height: 1.5;
	}

	#password-hint {
		line-height: 1.4;
	}
</style>
