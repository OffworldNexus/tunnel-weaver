<script lang="ts">
	/** A tiny inline sparkline. */
	import { areaPath, linePath, scale } from './chart';

	export let data: number[] = [];
	export let color = 'var(--tw-c1)';
	export let height = 34;
	export let width = 120;
	export let fill = true;
	export let strokeWidth = 1.6;

	const id = `spark-${Math.floor(Math.random() * 1e9).toString(36)}`;

	$: s = scale(data, width, height, 3);
	$: line = linePath(data, s);
	$: area = areaPath(data, s, height);
</script>

<svg
	class="spark"
	viewBox="0 0 {width} {height}"
	preserveAspectRatio="none"
	role="img"
	aria-hidden="true"
	style="--spark-color: {color}"
>
	{#if fill}
		<defs>
			<linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
				<stop offset="0%" stop-color={color} stop-opacity="0.28" />
				<stop offset="100%" stop-color={color} stop-opacity="0" />
			</linearGradient>
		</defs>
		<path d={area} fill="url(#{id})" />
	{/if}
	<path d={line} fill="none" stroke={color} stroke-width={strokeWidth} vector-effect="non-scaling-stroke" />
</svg>

<style lang="scss">
	.spark {
		display: block;
		width: 100%;
		height: 100%;
		overflow: visible;
	}
</style>
