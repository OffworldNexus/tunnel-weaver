<script lang="ts">
	/**
	 * Changes the password: the current one reauthenticates. A change ends every
	 * session, this one included, so it lands on sign-in with a notice.
	 */
	import { api } from '#lib/account/api';
	import { jsonForm } from '#lib/account/form';
	import NewPassword from '#lib/account/NewPassword.svelte';
	import { changePasswordSchema } from '#lib/account/schemas';
	import { flow } from '#lib/account/state';
	import { useSession } from '#lib/app/session.svelte';
	import { stepUp } from '#lib/app/upgrade';
	import { setMeta } from '#lib/console/meta.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Panel from '#lib/ui/Panel.svelte';
	import { resolve } from '$app/paths';

	setMeta({
		title: 'Change your password',
		subtitle: 'For your security, confirm your current password first.',
		crumbs: [{ label: 'Security', href: '/app/security' }, { label: 'Change password' }]
	});

	const session = useSession();

	// Refusals the relay scoped to one input, rendered on that field.
	let currentError = $state('');
	let newError = $state('');

	const sf = jsonForm(
		changePasswordSchema,
		{ current_password: '', new_password: '' },
		async (data) => {
			currentError = '';
			newError = '';
			// Success ends every session; do not let the guard see it before we leave.
			session.detach();
			const res = await api('POST', '/api/account/password', data, stepUp);
			if (!res.ok) {
				session.restart();
			}
			if (res.refused) {
				return;
			}
			if (res.ok) {
				// A full load (not a `goto`): the relay ended every session, this
				// one included, and a client-side navigation would let the console
				// report it as a spurious expiry. Sign-in shows the notice.
				flow.save({
					notice: 'Your password has been changed. Sign in with your new password.',
					email: session.user?.email
				});
				window.location.assign(resolve('/(auth)/sign-in'));
				return;
			}
			const error = res.error ?? 'We could not change your password. Please try again.';
			if (res.field === 'current_password') {
				currentError = error;
			} else if (res.field === 'new_password') {
				newError = error;
			} else {
				return error;
			}
		}
	);

	const { form, errors, message, submitting, enhance } = sf;

	const currentInvalid = $derived($errors.current_password?.[0] ?? currentError);
</script>

<div class="narrow">
	<Panel title="Change password">
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
					aria-invalid={currentInvalid ? 'true' : undefined}
					aria-describedby={currentInvalid ? 'current_password-error' : undefined}
				/>
				{#if currentInvalid}
					<p id="current_password-error" class="field__error" role="alert">{currentInvalid}</p>
				{/if}
			</div>

			<NewPassword
				id="new_password"
				bind:value={$form.new_password}
				error={$errors.new_password?.[0] ?? (newError || undefined)}
				disabled={$submitting}
			/>

			{#if $message}
				<p class="notice-error" role="alert">{$message}</p>
			{/if}

			<Keycap type="submit" loading={$submitting} disabled={$submitting} wide>
				{$submitting ? 'Saving…' : 'Change password'}
			</Keycap>
		</form>
	</Panel>

	<p class="note">
		Changing your password signs you out everywhere, including this device. You will be asked to
		sign in again with your new password.
	</p>
</div>

<style lang="scss">
	.narrow {
		width: 100%;
		max-width: 460px;
	}

	.form {
		gap: 16px;
		margin-top: 0;
	}

	.note {
		margin-top: 14px;
		color: var(--tw-muted);
		line-height: 1.5;
		font-size: 14px;
	}
</style>
