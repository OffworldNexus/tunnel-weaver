<script lang="ts">
	/**
	 * Modal dialog built on `@ark-ui/svelte`'s Dialog primitive, styled with the
	 * brand's cut-corner panel frame.
	 */
	import { Dialog } from '@ark-ui/svelte/dialog';
	import { Portal } from '@ark-ui/svelte/portal';

	import Icon from '#lib/ui/Icon.svelte';

	export let open = false;
	export let title = '';
	export let width = 520;
	/** Hide the default footer actions. */
	export let bare = false;
	export let onClose: (() => void) | undefined = undefined;

	function handleOpenChange(details: { open: boolean }) {
		open = details.open;
		if (!details.open) {
			onClose?.();
		}
	}
</script>

<Dialog.Root {open} onOpenChange={handleOpenChange} lazyMount unmountOnExit>
	<Portal>
		<Dialog.Backdrop class="ark-dialog-backdrop" />
		<Dialog.Positioner class="ark-dialog-positioner">
			<Dialog.Content class="ark-dialog-content" style="--dialog-w: {width}px">
				<header class="dialog__head">
					<Dialog.Title class="dialog__title">{title}</Dialog.Title>
					<Dialog.CloseTrigger class="dialog__close" aria-label="Close">
						<Icon name="close" size={18} />
					</Dialog.CloseTrigger>
				</header>
				<div class="dialog__body">
					<slot />
				</div>
				{#if !bare}
					<footer class="dialog__foot">
						<slot name="footer" />
					</footer>
				{/if}
			</Dialog.Content>
		</Dialog.Positioner>
	</Portal>
</Dialog.Root>

<style lang="scss">
	@use 'mixins' as *;

	:global([data-scope='dialog'][hidden]),
	:global([data-scope='dialog'][data-state='closed']) {
		display: none !important;
	}

	:global([data-scope='dialog'][data-part='backdrop']) {
		position: fixed;
		inset: 0;
		z-index: 70;
		background: rgb(11 6 4 / 0.6);
		backdrop-filter: blur(2px);
	}

	:global([data-scope='dialog'][data-part='positioner']) {
		position: fixed;
		inset: 0;
		z-index: 80;
		display: grid;
		place-items: center;
		padding: 16px;
		overflow-y: auto;
	}

	:global([data-scope='dialog'][data-part='content']) {
		@include cut-panel(16px, var(--tw-well), var(--tw-border), 1.5px);
		--tw-key-pedestal: #524943;
		width: min(var(--dialog-w, 520px), calc(100vw - 32px));
		max-height: calc(100svh - 48px);
		padding: 1.5px;
		color: var(--tw-text);
		box-shadow: var(--tw-shadow);
		display: flex;
		flex-direction: column;
		outline: none;
	}

	.dialog__head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		padding: 14px 16px;
		border-bottom: 1.5px solid var(--tw-border);
	}

	:global([data-scope='dialog'][data-part='title']) {
		margin: 0;
		font-family: var(--tw-heading);
		font-size: 17px;
		font-weight: 700;
	}

	:global([data-scope='dialog'][data-part='close-trigger']) {
		display: grid;
		place-items: center;
		width: 32px;
		height: 32px;
		border: 0;
		background: none;
		color: var(--tw-muted);
		cursor: pointer;
	}

	:global([data-scope='dialog'][data-part='close-trigger']:hover) {
		color: var(--tw-text);
		background: color-mix(in srgb, var(--tw-text) 8%, transparent);
	}

	.dialog__body {
		padding: 16px;
		overflow-y: auto;
	}

	.dialog__foot {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 10px;
		padding: 12px 16px;
		border-top: 1.5px solid var(--tw-border);
	}
</style>
