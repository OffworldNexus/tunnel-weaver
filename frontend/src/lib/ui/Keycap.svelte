<script lang="ts">
	export let type: 'button' | 'submit' = 'submit';
	export let disabled = false;
	export let loading = false;
	export let variant: 'primary' | 'ghost' = 'primary';
	export let wide = false;
	/** When set, the keycap renders as a link instead of a button. */
	export let href: string | undefined = undefined;
	export let onclick: ((event: MouseEvent) => void) | undefined = undefined;

	$: isLink = typeof href === 'string' && href.length > 0;
	$: classes = `keycap keycap--${variant}${wide ? ' keycap--wide' : ''}`;
	$: deactivated = disabled || loading;
</script>

<!-- The shape is built from layered, identically-clipped spans (pedestal, focus
     ring, cap frame, cap face) so the border and the focus ring both follow the
     10px cut corner. The label stays real text for the accessible name. -->
<svelte:element
	this={isLink ? 'a' : 'button'}
	class={classes}
	href={isLink ? href : undefined}
	type={isLink ? undefined : type}
	{onclick}
	disabled={isLink ? undefined : deactivated}
	aria-busy={isLink ? undefined : loading}
>
	<span class="keycap__art" aria-hidden="true">
		<span class="keycap__pedestal"></span>
		<span class="keycap__ring"><span class="keycap__ring-hole"></span></span>
		<span class="keycap__cap"><span class="keycap__face"></span></span>
	</span>
	<span class="keycap__label"><slot /></span>
</svelte:element>

<style lang="scss">
	@use 'mixins' as *;

	/* Keycap (Figma primitives): a 44px hit area holding a 34px cap that rests at
	   top:3px on a `--tw-key-pedestal` base at top:7px, with a 10px 45° cut on the
	   top-right. The border and the focus ring are each built from clipped layers,
	   so both follow the cut exactly. */
	.keycap {
		position: relative;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-height: 44px;
		padding: 0 20px;
		border: 0;
		background: transparent;
		color: var(--tw-on-confirm);
		font: 700 16px/1.4 var(--tw-sans);
		text-align: center;
		text-decoration: none;
		cursor: pointer;
		isolation: isolate;
	}

	.keycap:hover {
		text-decoration: none;
	}

	/* The layered geometry, shared shape primitives. */
	@include keycap-layers;
	@include keycap-focus-ring;

	.keycap__pedestal {
		background: var(--tw-key-pedestal);
	}

	.keycap__cap {
		background: var(--tw-border);
	}

	.keycap__face {
		background: var(--tw-deck);
	}

	/* Confirm: a solid cap with a subtle bevel and no distinct border. */
	.keycap--primary .keycap__cap {
		background: var(--tw-confirm);
	}

	.keycap--primary .keycap__face {
		inset: 0;
		background: var(--tw-confirm);
		@include cut-corner(10px);
		box-shadow:
			inset 0 1px 0 rgb(255 255 255 / 0.4),
			inset 0 -1px 0 rgb(0 0 0 / 0.15);
	}

	.keycap--primary:hover .keycap__face {
		background: var(--tw-confirm-hover);
	}

	/* Ghost: a 1.5px border that follows the cut, over the page surface. */
	.keycap--ghost {
		color: var(--tw-text);
	}

	.keycap--ghost .keycap__face {
		background: var(--tw-deck);
	}

	.keycap--ghost:hover .keycap__face {
		background: color-mix(in srgb, var(--tw-text) 10%, var(--tw-deck));
	}

	/* Press: the cap travels 4px onto the pedestal (70ms hard stop). */
	.keycap:active .keycap__cap {
		top: 7px;
		transition-duration: 70ms;
	}

	/* The shaped ring is the focus indicator; suppress the generic rectangular
	   outline the base `:focus-visible` rule would otherwise draw. */
	.keycap:focus-visible .keycap__ring {
		opacity: 1;
	}

	.keycap:focus-visible {
		outline: none;
	}

	/* Forced-colors users still need a visible indicator. */
	@media (forced-colors: active) {
		.keycap:focus-visible {
			outline: 2px solid CanvasText;
			outline-offset: 3px;
		}
	}

	.keycap--wide {
		width: 100%;
	}

	/* Disabled / busy */
	.keycap:disabled,
	.keycap[aria-disabled='true'] {
		cursor: not-allowed;
		color: var(--tw-muted);
	}

	.keycap:disabled .keycap__pedestal,
	.keycap[aria-disabled='true'] .keycap__pedestal {
		background: transparent;
	}

	.keycap:disabled .keycap__cap,
	.keycap[aria-disabled='true'] .keycap__cap {
		background: var(--tw-border);
	}

	.keycap:disabled .keycap__face,
	.keycap[aria-disabled='true'] .keycap__face {
		background: var(--tw-well);
		box-shadow: none;
	}

	.keycap[aria-busy='true'] {
		cursor: progress;
	}

	@media (prefers-reduced-motion: reduce) {
		.keycap__cap,
		.keycap__face,
		.keycap__ring {
			transition: none;
		}

		.keycap:active .keycap__cap {
			top: 3px;
		}
	}
</style>
