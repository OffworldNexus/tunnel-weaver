<script lang="ts">
	/**
	 * Ban / suspension modal built on the Ark UI Dialog: records a text annotation
	 * explaining why the user or organisation was banned, so raw criminal payload
	 * samples can be purged immediately while the reason and proof tally remain on
	 * the banned record.
	 */
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';

	import Dialog from './Dialog.svelte';

	export let open = false;
	export let title = 'Ban account?';
	export let confirmLabel = 'Ban & freeze tunnels';
	export let defaultNote = '';
	export let onConfirm: (note: string) => void = () => {};
	export let onClose: (() => void) | undefined = undefined;

	let note = '';
	let wasOpen = false;

	$: if (open && !wasOpen) {
		note = defaultNote;
	}
	$: wasOpen = open;

	function close() {
		open = false;
		onClose?.();
	}

	function submit() {
		if (!note.trim()) {
			return;
		}
		onConfirm(note.trim());
		open = false;
	}
</script>

<Dialog bind:open {title} width={480} {onClose}>
	<div class="ban-modal">
		<div class="ban-modal__alert">
			<Icon name="ban" size={18} />
			<div class="ban-modal__copy">
				<slot />
			</div>
		</div>

		<form class="stack" on:submit|preventDefault={submit}>
			<label for="ban-note-input" class="ban-modal__label">
				Ban annotation <span class="muted">(kept on the record; raw payload samples are purged)</span>
			</label>
			<textarea
				id="ban-note-input"
				class="control"
				rows="3"
				bind:value={note}
				placeholder="Record why this ban was enforced (e.g. confirmed PDQ hash matches on /media/albums; raw samples purged)…"
			></textarea>
		</form>
	</div>

	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={close}>Cancel</Keycap>
		<Keycap type="button" variant="danger" disabled={!note.trim()} onclick={submit}>
			<Icon name="ban" size={14} /> {confirmLabel}
		</Keycap>
	</svelte:fragment>
</Dialog>

<style lang="scss">
	.ban-modal {
		display: flex;
		flex-direction: column;
		gap: 16px;
	}

	.ban-modal__alert {
		display: flex;
		gap: 12px;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.55;
	}

	.ban-modal__alert :global(svg) {
		color: var(--tw-danger);
		flex: none;
		margin-top: 2px;
	}

	.ban-modal__copy {
		flex: 1;
	}

	.ban-modal__label {
		font-size: 13px;
		font-weight: 700;
	}

	.ban-modal__label .muted {
		font-weight: 400;
		font-size: 12px;
	}
</style>
