<script lang="ts">
	/**
	 * The password step-up popin, asking the account's password again.
	 *
	 * It is the console's form of the `confirm_password` step (WVR-165) and it is
	 * global: one instance serves every action that needs a level re-proven
	 * (`lib/app/stepup.svelte.ts` drives it, the root layout mounts it), so a
	 * sensitive action never grows a password form of its own, and the person
	 * never loses the page it happened on.
	 *
	 * It stays open until whoever asked says the check passed, so a wrong
	 * password is answered on the field rather than by a popin that closed.
	 */
	import Dialog from '#lib/ui/Dialog.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';

	interface Props {
		open?: boolean;
		title?: string;
		/** The refusal to show on the field; the caller owns it. */
		error?: string;
		/** Whether a check is in flight. */
		busy?: boolean;
		/** Receives the typed password; the caller checks it. */
		onConfirm?: (password: string) => void;
		onClose?: () => void;
	}

	let {
		open = $bindable(false),
		title = 'Confirm your password',
		error = '',
		busy = false,
		onConfirm = () => {},
		onClose = undefined
	}: Props = $props();

	let password = $state('');

	/**
	 * Clears the field whenever the dialog opens.
	 *
	 * The caller drives `open` (it closes this dialog to hand over to the next
	 * step of the flow), so `close()` alone cannot be the only place that
	 * forgets the password: a step-up left the field holding the password from
	 * last time, which is the opposite of what this dialog is for.
	 */
	$effect(() => {
		if (open) {
			password = '';
		}
	});

	/** Closes, and forgets the password. */
	function close() {
		password = '';
		open = false;
		onClose?.();
	}

	function submit() {
		if (password === '' || busy) {
			return;
		}
		onConfirm(password);
	}
</script>

<Dialog bind:open {title} width={460} onClose={close}>
	{#snippet footer()}
		<Keycap type="button" variant="key" onclick={close} disabled={busy}>Cancel</Keycap>
		<Keycap type="button" variant="key" onclick={submit} loading={busy} disabled={password === ''}>
			<Icon name="lock" size={14} /> Confirm
		</Keycap>
	{/snippet}

	<div class="confirm-password">
		<div class="confirm-password__lead">
			<Icon name="lock" size={18} />
			<div class="confirm-password__copy">
				<p>
					Your password is what says it is you. It is only taken at its word for a few minutes at a
					time, so an action that matters asks for it again.
				</p>
			</div>
		</div>

		<form
			class="stack"
			onsubmit={(event) => {
				event.preventDefault();
				submit();
			}}
		>
			<div class="field">
				<label for="confirm-password-input">Password</label>
				<input
					id="confirm-password-input"
					class="control"
					type="password"
					autocomplete="current-password"
					bind:value={password}
					disabled={busy}
					aria-invalid={error ? 'true' : undefined}
					aria-describedby={error ? 'confirm-password-error' : undefined}
				/>
				{#if error}
					<p id="confirm-password-error" class="field__error" role="alert">{error}</p>
				{/if}
			</div>
		</form>
	</div>
</Dialog>

<style lang="scss">
	.confirm-password {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	// The same lede block as the sibling `ConfirmDeleteDialog`, with a neutral
	// lock rather than a danger icon: the two dialogs of one flow should read as
	// one sequence, and only the second of them is destructive.
	.confirm-password__lead {
		display: flex;
		gap: 12px;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.55;
	}

	.confirm-password__lead :global(svg) {
		flex: none;
		margin-top: 2px;
	}

	.confirm-password__copy {
		flex: 1;
	}

	// A dialog asks in the console's compact in-dialog rhythm — the 14px label
	// over the 38px `.control`, as in `ConfirmDeleteDialog` and the reference
	// console's Change password dialog — not the page-form `.field` scale (16px
	// label, 44px control). Without this, `.field input` outweighs the input's
	// own `.control` and this field renders a size larger than its sibling.
	.confirm-password .field > label {
		font-size: 14px;
		font-weight: 700;
	}

	.confirm-password .field input {
		height: 38px;
		padding: 0 10px;
		font-size: 14px;
	}
</style>
