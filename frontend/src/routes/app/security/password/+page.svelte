<script lang="ts">
	/**
	 * Change your password (WVR-50), under the signed-in shell.
	 *
	 * No frame is drawn for this form, so it mirrors "04 / Set your password":
	 * the current password for reauthentication and the new password with the
	 * shared strength meter. A successful change ends **every** session —
	 * this one included — so it lands on sign-in with a notice, exactly like a
	 * reset does.
	 */
	import { goto } from '$app/navigation';
	import { superForm } from 'sveltekit-superforms';
	import { valibot } from 'sveltekit-superforms/adapters';
	import { api, fieldOf, messageOf } from '#lib/account/api';
	import { ensureConfig } from '#lib/account/config';
	import { saveFlow } from '#lib/account/flow';
	import { changePasswordSchema } from '#lib/account/schemas';
	import { csrfToken } from '#lib/account/session';
	import PasswordStrength from '#lib/account/PasswordStrength.svelte';
	import { me } from '#lib/app/me';
	import { href } from '#lib/app/paths';
	import Keycap from '#lib/ui/Keycap.svelte';

	// The relay owns the minimum; the client mirrors it for guidance.
	const limits = { min: 8 };
	let minLength = limits.min;
	// The toggle sits under the new-password hint (as Figma draws it) and reveals
	// the new password; the current password stays masked.
	let showPassword = false;
	// Refusals the relay scoped to one input, rendered on that field.
	let currentError = '';
	let newError = '';

	ensureConfig()
		.then((cfg) => {
			limits.min = cfg.min_password_length;
			minLength = cfg.min_password_length;
		})
		.catch(() => {
			// The relay still enforces the true minimum on submit.
		});

	const sf = superForm(
		{ current_password: '', new_password: '' },
		{
			validators: valibot(changePasswordSchema(() => limits.min)),
			clearOnSubmit: 'errors-and-message',
			onSubmit: async ({ cancel }) => {
				cancel();
				currentError = '';
				newError = '';
				const result = await sf.validateForm({ update: true });
				if (!result.valid) return;

				// The change is CSRF-protected: without the cookie, refuse locally
				// rather than send a request the relay would reject anyway.
				const csrf = csrfToken();
				if (!csrf) {
					sf.message.set(
						'We could not change your password safely. Reload the page and try again.'
					);
					return;
				}

				try {
					const res = await api<{ outcome: string }>('/api/account/password', {
						method: 'POST',
						csrf,
						body: {
							current_password: result.data.current_password,
							new_password: result.data.new_password
						}
					});
					if (res.ok && res.data?.outcome === 'changed') {
						saveFlow({
							notice: 'Your password has been changed. Sign in with your new password.',
							noticeKind: 'success',
							email: $me?.email ?? undefined
						});
						await goto(href('/sign-in'));
						return;
					}
					// Place a field-scoped refusal on the field it belongs to; anything
					// else stays form-wide.
					const message = messageOf(
						res.data,
						'We could not change your password. Please try again.'
					);
					switch (fieldOf(res.data)) {
						case 'current_password':
							currentError = message;
							break;
						case 'new_password':
							newError = message;
							break;
						default:
							sf.message.set(message);
					}
				} catch {
					sf.message.set('We could not reach the server. Check your connection and try again.');
				}
			}
		}
	);

	const { form, errors, message, submitting, enhance } = sf;

	// Link each field to its message so screen readers announce it with the
	// control, not just through the live region.
	$: newDescribedBy =
		$errors.new_password || newError ? 'new_password-hint new_password-error' : 'new_password-hint';
	$: currentDescribedBy =
		$errors.current_password || currentError ? 'current_password-error' : undefined;
</script>

<svelte:head>
	<title>Change your password · Tunnel Weaver</title>
</svelte:head>

<h1 id="app-title">Change your password</h1>
<p class="lede">For your security, confirm your current password first.</p>

<form class="form" method="POST" use:enhance novalidate>
	<div class="field">
		<label for="current_password">Current password</label>
		<input
			id="current_password"
			name="current_password"
			type="password"
			autocomplete="current-password"
			bind:value={$form.current_password}
			disabled={$submitting}
			aria-invalid={$errors.current_password || currentError ? 'true' : undefined}
			aria-describedby={currentDescribedBy}
		/>
		{#if $errors.current_password}
			<p id="current_password-error" class="field__error" aria-live="polite">
				{$errors.current_password[0]}
			</p>
		{:else if currentError}
			<p id="current_password-error" class="field__error" role="alert" aria-live="assertive">
				{currentError}
			</p>
		{/if}
	</div>

	<div class="field">
		<label for="new_password">New password</label>
		<input
			id="new_password"
			name="new_password"
			type={showPassword ? 'text' : 'password'}
			autocomplete="new-password"
			placeholder="Create a unique password"
			bind:value={$form.new_password}
			disabled={$submitting}
			aria-invalid={$errors.new_password || newError ? 'true' : undefined}
			aria-describedby={newDescribedBy}
		/>

		<PasswordStrength value={$form.new_password} />

		{#if $errors.new_password}
			<p id="new_password-error" class="field__error" aria-live="polite">
				{$errors.new_password[0]}
			</p>
		{:else if newError}
			<p id="new_password-error" class="field__error" role="alert" aria-live="assertive">
				{newError}
			</p>
		{/if}

		<p id="new_password-hint" class="hint">
			Use at least {minLength} characters. A longer, unique passphrase beats a short,
			complicated one.
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
		{$submitting ? 'Saving…' : 'Change password'}
	</Keycap>
</form>

<p class="note">
	Changing your password signs you out everywhere, including this device. You will be asked to
	sign in again with your new password.
</p>

<p class="switch"><a href={href('/app/security')}>Back to Security</a></p>

<style lang="scss">
	/* The drawn "04 / Set your password" rhythm: a uniform 16px gap between the
	   heading, the lede, every form row, the note and the back link. The form
	   has no frame of its own, so it inherits that reference's spacing. */
	.lede {
		margin-top: 16px;
	}

	.form {
		gap: 16px;
		margin-top: 16px;
	}

	/* The drawn "Link / Show password" row is 44px tall; the shared `.toggle`
	   only reserves 32px, which is under the 44px tap-target floor. */
	.toggle {
		display: flex;
		align-items: center;
		min-height: 44px;
	}

	/* The sign-out-everywhere note under the form. */
	.note {
		margin-top: 16px;
		color: var(--tw-muted);
		font-size: 16px;
		line-height: 1.5;
	}

	.switch {
		margin-top: 16px;
	}

	/* The drawn "Link / Back to sign in" row is 44px tall; the bare text is
	   only ~19px, so reserve the tap-target height. */
	.switch a {
		display: inline-flex;
		align-items: center;
		min-height: 44px;
	}
</style>
