<script lang="ts">
	/** Security overview: what the account signs in with. */
	import { api } from '#lib/account/api';
	import { notify } from '#lib/account/notices';
	import { flow } from '#lib/account/state';
	import { atLeast, useSession } from '#lib/app/session.svelte';
	import { climb, stepUp } from '#lib/app/upgrade';
	import { setMeta } from '#lib/console/meta.svelte';
	import ConfirmDeleteDialog from '#lib/ui/ConfirmDeleteDialog.svelte';
	import ConfirmPasswordDialog from '#lib/ui/ConfirmPasswordDialog.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Panel from '#lib/ui/Panel.svelte';
	import { resolve } from '$app/paths';

	setMeta({
		title: 'Security',
		subtitle: 'Choose how you sign in. Protect your account.',
		crumbs: [{ label: 'Security' }]
	});

	let confirming = $state(false);
	let confirmingPassword = $state(false);
	let passwordError = $state('');
	let busy = $state(false);
	/**
	 * The address the person already typed back, kept while the password step
	 * runs so the delete resumes where it left off instead of asking again.
	 */
	let pendingAddress = $state('');

	const session = useSession();

	/**
	 * What the user must type back: the address when there is one, else the
	 * display name — the same pair the relay re-checks server-side.
	 */
	const expected = $derived(session.user?.email || session.user?.name || '');

	/**
	 * Deleting needs `Certain` — the password proven moments ago — so the
	 * password step opens first, and the confirmation that follows it is the
	 * last word. A session that is already `Certain` (someone who has just
	 * signed in) goes straight to the confirmation.
	 */
	function beginDelete() {
		if (atLeast(session.level, 'certain')) {
			confirming = true;
			return;
		}
		pendingAddress = '';
		passwordError = '';
		confirmingPassword = true;
	}

	/** The step-up itself: ask the relay to prove the password again. */
	async function confirmPassword(password: string) {
		passwordError = '';
		busy = true;
		const res = await api('POST', '/api/account/confirm-password', { password }, stepUp);
		busy = false;
		if (res.refused) {
			return;
		}
		if (!res.ok) {
			passwordError = res.error ?? 'That is not your password.';
			return;
		}
		// The relay records the proof; wait for the session stream to report the
		// new level, so the retry is not refused for a frame.
		await session.reached('certain');
		confirmingPassword = false;
		passwordError = '';
		if (pendingAddress) {
			// The person had already confirmed the deletion; finish it.
			const address = pendingAddress;
			pendingAddress = '';
			await deleteAccount(address);
			return;
		}
		confirming = true;
	}

	async function deleteAccount(address: string) {
		busy = true;
		// Success ends every session; do not let the guard see it before we leave.
		session.detach();
		const res = await api('POST', '/api/account/delete', { address }, async (required, paths) => {
			// The proof aged out while the confirmation was open, or the level was
			// never enough: whatever the way up names, take it and come back to the
			// confirmation the person already gave.
			if (paths[0]?.[0]?.step !== 'confirm_password') {
				await climb(required, paths);
				return;
			}
			pendingAddress = address;
			confirming = false;
			passwordError = '';
			confirmingPassword = true;
		});
		busy = false;
		confirming = false;
		if (!res.ok) {
			session.restart();
			if (res.refused) {
				return;
			}
			notify('error', res.error ?? 'We could not delete your account. Please try again.');
			return;
		}
		// The relay removed every session and cleared both cookies. A full load
		// (not a `goto`) keeps the console from watching the session lapse and
		// reporting a spurious "session expired"; sign-in shows the notice.
		flow.save({ notice: 'Your account and all its data have been deleted.' });
		window.location.assign(resolve('/(auth)/sign-in'));
	}
</script>

<Panel
	title="Password"
	subtitle="Your password signs you in and authorises changes to the account."
>
	{#snippet actions()}
		<Keycap href={resolve('/app/security/password')} variant="key" size="sm">
			<Icon name="lock" size={14} /> Change password
		</Keycap>
	{/snippet}

	{#if session.user?.has_password}
		<p class="state"><Icon name="check" size={16} /> Password is set</p>
	{:else}
		<p class="state">No password is set</p>
	{/if}
</Panel>

<Panel
	title="Two-factor authentication"
	subtitle="A second factor protects your account even if your password leaks. It is always on."
>
	<p class="state"><Icon name="check" size={16} /> Enabled · email codes</p>
	<p class="state__note">
		Every sign-in sends a one-time code to
		<strong>{session.user?.email || 'your address'}</strong>. The relay's email provider is
		therefore required, and there is no way to turn the second factor off.
	</p>
</Panel>

<Panel danger title="Danger zone" subtitle="Irreversible actions. There is no way back.">
	<div class="danger">
		<div class="danger__copy">
			<p class="danger__title">Delete your account</p>
			<p class="danger__note">
				Removes your account, unpairs every machine and tunnel, and deletes all of your usage
				history. This cannot be undone.
			</p>
		</div>
		<Keycap type="button" variant="danger" disabled={busy} onclick={beginDelete}>
			<Icon name="trash" size={14} /> Delete account
		</Keycap>
	</div>
</Panel>

<ConfirmPasswordDialog
	bind:open={confirmingPassword}
	error={passwordError}
	{busy}
	onConfirm={confirmPassword}
>
	<p>
		Deleting your account asks for your password first: it means the console has not simply been
		left open and signed in. We keep it for a few minutes, then ask again.
	</p>
</ConfirmPasswordDialog>

<ConfirmDeleteDialog
	bind:open={confirming}
	caseInsensitive
	title="Delete your account?"
	{expected}
	confirmLabel="Delete account"
	cancelLabel="Keep my account"
	onConfirm={deleteAccount}
>
	<p>
		This permanently deletes your account, every paired machine and tunnel, and all of your usage
		history. Nothing is retained and nothing can be recovered.
	</p>
</ConfirmDeleteDialog>

<style lang="scss">
	.state {
		display: flex;
		align-items: center;
		gap: 8px;
		margin: 0;
		color: var(--tw-muted);
	}

	.state :global(svg) {
		color: var(--tw-online);
	}

	.state__note {
		margin: 8px 0 0;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.5;
		max-width: 60ch;
	}

	.danger {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
	}

	.danger__copy {
		min-width: 0;
	}

	.danger__title {
		font-weight: 700;
		margin-bottom: 2px;
	}

	.danger__note {
		margin: 0;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.5;
		max-width: 60ch;
	}
</style>
