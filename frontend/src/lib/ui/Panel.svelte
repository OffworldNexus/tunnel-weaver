<script lang="ts">
	import type { Snippet } from 'svelte';

	/**
	 * A cut-corner surface. The header is optional; when a `title` or an
	 * `actions` snippet is present it renders a bordered strip above the body.
	 */
	interface Props {
		title?: string;
		subtitle?: string;
		/** Remove the body padding (for tables and full-bleed content). */
		flush?: boolean;
		/** The corner cut in px; smaller panels use a tighter cut. */
		cut?: number;
		/** Keep the body at a fixed height and scroll (for feeds). */
		scroll?: boolean;
		actions?: Snippet;
		footer?: Snippet;
		children?: Snippet;
	}

	let {
		title = '',
		subtitle = '',
		flush = false,
		cut = 16,
		scroll = false,
		actions,
		footer,
		children
	}: Props = $props();
</script>

<section class="panel" style="--cut: {cut}px" aria-label={title || undefined}>
	{#if title || actions !== undefined}
		<header class="panel__head">
			<div class="panel__titles">
				{#if title}<h2 class="panel__title">{title}</h2>{/if}
				{#if subtitle}<p class="panel__subtitle">{subtitle}</p>{/if}
			</div>
			<div class="panel__actions">
				{@render actions?.()}
			</div>
		</header>
	{/if}
	<div class="panel__body" class:flush class:scroll>
		{@render children?.()}
	</div>
	{#if footer !== undefined}
		<footer class="panel__foot">{@render footer?.()}</footer>
	{/if}
</section>

<style lang="scss">
	@use 'mixins' as *;

	.panel {
		position: relative;
		display: flex;
		flex-direction: column;
		min-width: 0;
		padding: 1.5px;
		--tw-key-pedestal: #524943;
		@include cut-panel(var(--cut, 16px), var(--tw-well), var(--tw-border), 1.5px);
	}

	.panel__head {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: 12px;
		padding: 14px 16px;
		border-bottom: 1.5px solid var(--tw-border);
	}

	.panel__titles {
		min-width: 0;
	}

	.panel__title {
		font-family: var(--tw-heading);
		font-size: 16px;
		font-weight: 700;
		line-height: 1.3;
	}

	.panel__subtitle {
		margin-top: 2px;
		color: var(--tw-muted);
		font-size: 13px;
		line-height: 1.4;
	}

	.panel__actions {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 8px;
	}

	.panel__body {
		min-width: 0;
		flex: 1 1 auto;
		padding: 16px;
		/* Let wide tables scroll inside the panel rather than clip. */
		overflow-x: auto;
	}

	.panel__body.flush {
		padding: 0;
	}

	.panel__body.scroll {
		max-height: 460px;
		overflow-y: auto;
		overscroll-behavior: contain;
	}

	.panel__foot {
		padding: 12px 16px;
		border-top: 1.5px solid var(--tw-border);
		color: var(--tw-muted);
		font-size: 13px;
	}
</style>
