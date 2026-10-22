<script lang="ts">
	/** The toast viewport, mounted once in the root layout; see `notify()`. */
	import { Toast, Toaster, type ToastOptions } from '@ark-ui/svelte';

	import { toaster } from '#lib/account/notices';
</script>

<Toaster {toaster} class="toaster">
	{#snippet children(toast: () => ToastOptions)}
		<Toast.Root class="toast">
			<Toast.Title class="toast__title">{toast().title}</Toast.Title>
			<Toast.CloseTrigger class="toast__close" aria-label="Dismiss message">×</Toast.CloseTrigger>
		</Toast.Root>
	{/snippet}
</Toaster>

<style lang="scss">
	/* Ark UI renders these elements from inside its own components, so Svelte's
	   scope class cannot reach them. Target the primitive's data attributes
	   globally instead — this file is the only place that styles the toast.

	   The positioning, stack offset, scale, opacity and collapse height are all
	   driven by CSS custom properties the machine writes on the root, so the
	   enter/exit and stacking animations come for free from transitioning them. */
	:global([data-scope='toast'][data-part='root']) {
		position: absolute;
		inset-inline: 0;
		/* The machine pins the group to the viewport edges with inline styles, so
		   cap the readable measure here and centre each toast within it. */
		margin-inline: auto;
		width: min(100%, 416px);
		translate: var(--x, 0) var(--y, 0);
		scale: var(--scale, 1);
		z-index: var(--z-index, 1);
		opacity: var(--opacity, 1);
		height: var(--height, auto);
		display: flex;
		align-items: flex-start;
		gap: 12px;
		padding: 12px 14px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
		color: var(--tw-text);
		font-size: 14px;
		box-shadow: 0 8px 24px rgb(11 6 4 / 0.14);
		will-change: translate, scale, opacity;
		transition:
			translate 260ms cubic-bezier(0.21, 1.02, 0.73, 1),
			scale 260ms cubic-bezier(0.21, 1.02, 0.73, 1),
			opacity 220ms ease;
	}

	:global([data-scope='toast'][data-part='root'][data-state='closed']) {
		transition:
			translate 200ms ease-in,
			opacity 160ms ease-in;
	}

	:global([data-scope='toast'][data-part='root'][data-type='error']) {
		border-color: var(--tw-danger);
		color: var(--tw-danger);
	}

	:global([data-scope='toast'][data-part='root'][data-type='success']) {
		border-color: var(--tw-success);
		color: var(--tw-success);
	}

	:global([data-scope='toast'][data-part='title']) {
		flex: 1;
	}

	:global([data-scope='toast'][data-part='close-trigger']) {
		border: 0;
		background: none;
		color: inherit;
		font-size: 1.15rem;
		line-height: 1;
		cursor: pointer;
		opacity: 0.7;
	}

	:global([data-scope='toast'][data-part='close-trigger']:hover) {
		opacity: 1;
	}

	@media (prefers-reduced-motion: reduce) {
		:global([data-scope='toast'][data-part='root']),
		:global([data-scope='toast'][data-part='root'][data-state='closed']) {
			transition: none;
		}
	}
</style>
