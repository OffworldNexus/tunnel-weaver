<script lang="ts">
	/** Cycles the theme preference: auto → light → dark. */
	import Icon from '#lib/ui/Icon.svelte';
	import type { IconName } from '#lib/ui/icons';

	import { cycleTheme, theme } from './theme';

	/** `icon` is the bare top-bar form; `footer` is the labelled sidebar one. */
	export let variant: 'icon' | 'footer' = 'icon';

	$: label =
		$theme === 'auto' ? 'Theme: system' : $theme === 'light' ? 'Theme: light' : 'Theme: dark';
	$: icon = ($theme === 'light' ? 'sun' : $theme === 'dark' ? 'moon' : 'layers') as IconName;
</script>

<button
	class="theme theme--{variant}"
	type="button"
	on:click={cycleTheme}
	title={label}
	aria-label={label}
>
	<Icon name={icon} size={variant === 'footer' ? 15 : 18} />
	{#if variant === 'footer'}<span class="theme__label">{label}</span>{/if}
</button>

<style lang="scss">
	.theme {
		display: inline-flex;
		align-items: center;
		border: 0;
		background: none;
		color: var(--tw-muted);
		cursor: pointer;
	}

	.theme--icon {
		justify-content: center;
		width: 36px;
		height: 36px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
		color: var(--tw-text);
	}

	.theme--icon:hover {
		background: var(--tw-raised);
	}

	.theme--footer {
		gap: 8px;
		min-height: 36px;
		padding: 0 10px;
		border-radius: var(--tw-radius);
		font: 700 13px/1 var(--tw-sans);
	}

	.theme--footer:hover {
		background: color-mix(in srgb, var(--tw-text) 7%, transparent);
		color: var(--tw-text);
	}
</style>
