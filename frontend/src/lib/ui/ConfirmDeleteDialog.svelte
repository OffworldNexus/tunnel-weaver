<script lang="ts">
	/**
	 * Destructive confirmation modal built on the Ark UI Dialog: requires typing
	 * back the target's exact name/slug before the danger keycap unlocks.
	 */
	import Dialog from '#lib/ui/Dialog.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';

	export let open = false;
	export let title = 'Confirm deletion';
	/** The exact string the user must type back to unlock the confirm button. */
	export let expected = '';
	export let confirmLabel = 'Delete';
	export let cancelLabel = 'Cancel';
	export let onConfirm: () => void = () => {};
	export let onClose: (() => void) | undefined = undefined;

	let typed = '';

	$: matches = expected !== '' && typed.trim() === expected;

	/** Closes the dialog and clears the confirmation field for the next open. */
	function close() {
		typed = '';
		open = false;
		onClose?.();
	}

	function submit() {
		if (!matches) {
			return;
		}
		typed = '';
		onConfirm();
	}
</script>

<Dialog bind:open {title} width={460} onClose={close}>
	<div class="confirm-delete">
		<div class="confirm-delete__alert">
			<Icon name="alert" size={18} />
			<div class="confirm-delete__copy">
				<slot />
			</div>
		</div>

		<form class="stack" on:submit|preventDefault={submit}>
			<label for="confirm-delete-input" class="confirm-delete__prompt">
				Type <code class="mono confirm-delete__expected">{expected}</code> to confirm:
			</label>
			<input
				id="confirm-delete-input"
				class="control mono"
				type="text"
				bind:value={typed}
				placeholder={expected}
				autocomplete="off"
				spellcheck="false"
			/>
		</form>
	</div>

	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={close}>{cancelLabel}</Keycap>
		<Keycap type="button" variant="danger" disabled={!matches} onclick={submit}>
			<Icon name="trash" size={14} />
			{confirmLabel}
		</Keycap>
	</svelte:fragment>
</Dialog>

<style lang="scss">
	.confirm-delete {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	.confirm-delete__alert {
		display: flex;
		gap: 12px;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.55;
	}

	.confirm-delete__alert :global(svg) {
		color: var(--tw-danger);
		flex: none;
		margin-top: 2px;
	}

	.confirm-delete__copy {
		flex: 1;
	}

	.confirm-delete__prompt {
		font-size: 13px;
		font-weight: 600;
		color: var(--tw-muted);
	}

	.confirm-delete__expected {
		padding: 2px 6px;
		border: 1px solid var(--tw-border);
		background: var(--tw-raised);
		color: var(--tw-text);
		font-weight: 700;
	}
</style>
