<script lang="ts">
	/** Inline stroke icons, `currentColor` only. Names live in `icons.ts`. */
	import { ICON_PATHS, type IconName } from './icons';

	interface Props {
		name: IconName;
		size?: number;
	}

	let { name, size = 24 }: Props = $props();

	const paths = $derived(ICON_PATHS[name]);
</script>

<svg
	class="icon"
	viewBox="0 0 24 24"
	width={size}
	height={size}
	fill={name === 'github' ? 'currentColor' : 'none'}
	stroke={name === 'github' ? 'none' : 'currentColor'}
	stroke-width="1.7"
	stroke-linecap="round"
	stroke-linejoin="round"
	aria-hidden="true"
	focusable="false"
>
	{#each paths as d (d)}
		<path {d} />
	{/each}
</svg>

<style lang="scss">
	.icon {
		display: block;
		flex: none;
	}
</style>
