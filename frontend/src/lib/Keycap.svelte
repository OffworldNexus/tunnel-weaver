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
