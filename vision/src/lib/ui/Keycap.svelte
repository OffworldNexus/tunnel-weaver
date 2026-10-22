<script lang="ts">
	export let type: 'button' | 'submit' = 'submit';
	export let disabled = false;
	export let loading = false;
	export let variant: 'primary' | 'key' | 'danger' | 'ghost' = 'primary';
	export let size: 'md' | 'sm' = 'md';
	export let wide = false;
	/** When set, the keycap renders as a link instead of a button. */
	export let href: string | undefined = undefined;
	/** Link attributes, applied only when `href` renders an anchor (e.g. external links). */
	export let target: '_self' | '_blank' | '_parent' | '_top' | undefined = undefined;
	export let rel: string | undefined = undefined;
	export let title: string | undefined = undefined;
	export let ariaLabel: string | undefined = undefined;
	export let onclick: ((event: MouseEvent) => void) | undefined = undefined;

	$: isLink = Boolean(href);
	$: classes = `keycap keycap--${variant} keycap--${size}${wide ? ' keycap--wide' : ''}`;
	$: deactivated = disabled || loading;
</script>

<!-- The shape is built from layered, identically-clipped spans (pedestal, focus
     ring, cap frame, cap face) so the border and the focus ring both follow the
     cut corner. The label stays real text for the accessible name. -->
<!-- svelte-ignore a11y_no_static_element_interactions (it is always an <a> or a <button>) -->
<svelte:element
	this={isLink ? 'a' : 'button'}
	class={classes}
	href={isLink ? href : undefined}
	target={isLink ? target : undefined}
	rel={isLink ? rel : undefined}
	type={isLink ? undefined : type}
	{title}
	aria-label={ariaLabel}
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
		padding: 0 18px 4px;
		border: 0;
		background: transparent;
		color: var(--tw-on-confirm);
		font: 700 15px/1.4 var(--tw-sans);
		text-align: center;
		text-decoration: none;
		white-space: nowrap;
		cursor: pointer;
		isolation: isolate;
	}

	.keycap:hover {
		text-decoration: none;
	}

	/* The layered geometry, shared shape primitives. */
	@include keycap-layers;
	@include keycap-focus-ring;

	.keycap__label {
		display: inline-flex;
		align-items: center;
		gap: 7px;
		transition: transform 100ms ease;
	}

	.keycap__pedestal {
		background: var(--tw-key-pedestal);
	}

	.keycap__cap {
		background: var(--tw-border);
	}

	.keycap__face {
		background: var(--tw-deck);
	}

	/* Compact size (`sm`) for dense toolbars and table row actions: a 34px hit
	   area holding a 26px cap at top:2px over a pedestal at top:5px, 8px cut. */
	.keycap--sm {
		min-height: 34px;
		padding: 0 12px 3px;
		font-size: 12px;
	}

	.keycap--sm .keycap__pedestal {
		top: 5px;
		height: 26px;
		@include cut-corner(8px);
	}

	.keycap--sm .keycap__cap {
		top: 2px;
		height: 26px;
		@include cut-corner(8px);
	}

	.keycap--sm .keycap__face {
		@include cut-inset(8px, 0.9px);
	}

	.keycap--sm .keycap__ring {
		top: 0;
		height: 30px;
		@include cut-corner(9.17px);
	}

	.keycap--sm .keycap__ring-hole {
		@include cut-corner(8px);
	}

	/* Confirm (`primary`): a solid cap with a subtle bevel and no distinct border. */
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

	.keycap--sm.keycap--primary .keycap__face {
		@include cut-corner(8px);
	}

	.keycap--primary:hover .keycap__face {
		background: var(--tw-confirm-hover);
	}

	/* Key (`key`): Figma `key`/`onKey` dark neutral cap with light text, used by
	   panel secondary actions. */
	.keycap--key {
		color: var(--tw-on-key);
	}

	.keycap--key .keycap__face {
		background: var(--tw-key);
	}

	.keycap--key:hover .keycap__face {
		background: color-mix(in srgb, var(--tw-on-key) 12%, var(--tw-key));
	}

	/* Danger (`danger`): crimson cap with light text and a dark crimson pedestal. */
	.keycap--danger {
		color: #fefaf3;
	}

	.keycap--danger .keycap__pedestal {
		background: #521d19;
	}

	.keycap--danger .keycap__cap {
		background: #c85a52;
	}

	.keycap--danger .keycap__face {
		background: #a44039;
	}

	.keycap--danger:hover .keycap__face {
		background: #b84c44;
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

	/* Press: the cap and label travel onto the pedestal (70ms hard stop). */
	.keycap:active:not(:disabled) .keycap__cap {
		top: 7px;
		transition-duration: 70ms;
	}

	.keycap:active:not(:disabled) .keycap__label {
		transform: translateY(4px);
		transition-duration: 70ms;
	}

	.keycap--sm:active:not(:disabled) .keycap__cap {
		top: 5px;
	}

	.keycap--sm:active:not(:disabled) .keycap__label {
		transform: translateY(3px);
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
	.keycap:disabled {
		cursor: not-allowed;
		color: var(--tw-muted);
	}

	.keycap:disabled .keycap__pedestal {
		background: transparent;
	}

	.keycap:disabled .keycap__cap {
		background: var(--tw-border);
	}

	.keycap:disabled .keycap__face {
		background: var(--tw-well);
		box-shadow: none;
	}

	.keycap[aria-busy='true'] {
		cursor: progress;
	}

	@media (prefers-reduced-motion: reduce) {
		.keycap__cap,
		.keycap__face,
		.keycap__ring,
		.keycap__label {
			transition: none;
		}

		.keycap:active:not(:disabled) .keycap__cap {
			top: 3px;
		}

		.keycap--sm:active:not(:disabled) .keycap__cap {
			top: 2px;
		}

		.keycap:active:not(:disabled) .keycap__label {
			transform: none;
		}
	}
</style>
