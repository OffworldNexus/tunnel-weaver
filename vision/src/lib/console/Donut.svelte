<script lang="ts">
	/** A donut breakdown, e.g. HTTP status classes. */
	export let segments: { label: string; value: number; color: string }[] = [];
	export let size = 148;
	export let thickness = 14;
	export let centerLabel = '';
	export let centerSub = '';

	const R = 50;
	const C = 2 * Math.PI * R;

	$: total = segments.reduce((a, s) => a + s.value, 0) || 1;
	$: arcs = (() => {
		let offset = 0;
		return segments.map((seg) => {
			const frac = seg.value / total;
			const arc = { ...seg, dash: frac * C, offset: -offset, frac };
			offset += frac * C;
			return arc;
		});
	})();
</script>

<div class="donut" style="--size: {size}px">
	<svg viewBox="0 0 120 120" role="img" aria-label="Distribution">
		<circle class="donut__track" cx="60" cy="60" r={R} fill="none" stroke-width={thickness} />
		{#each arcs as arc (arc.label)}
			<circle
				cx="60"
				cy="60"
				r={R}
				fill="none"
				stroke={arc.color}
				stroke-width={thickness}
				stroke-dasharray="{arc.dash} {C - arc.dash}"
				stroke-dashoffset={arc.offset}
				transform="rotate(-90 60 60)"
				stroke-linecap="butt"
			/>
		{/each}
	</svg>
	<div class="donut__center">
		<span class="donut__label mono">{centerLabel}</span>
		{#if centerSub}<span class="donut__sub">{centerSub}</span>{/if}
	</div>
	<ul class="donut__legend">
		{#each arcs as arc (arc.label)}
			<li>
				<span class="donut__swatch" style="background: {arc.color}"></span>
				<span class="donut__name">{arc.label}</span>
				<span class="donut__pct mono">{(arc.frac * 100).toFixed(1)}%</span>
			</li>
		{/each}
	</ul>
</div>

<style lang="scss">
	.donut {
		display: flex;
		align-items: center;
		gap: 20px;
		flex-wrap: wrap;
	}

	.donut svg {
		width: var(--size, 148px);
		height: var(--size, 148px);
		flex: none;
	}

	.donut {
		position: relative;
	}

	.donut__center {
		position: absolute;
		top: calc(var(--size, 148px) / 2);
		left: calc(var(--size, 148px) / 2);
		transform: translate(-50%, -50%);
		display: flex;
		flex-direction: column;
		align-items: center;
		pointer-events: none;
	}

	.donut__label {
		font-size: 20px;
		font-weight: 700;
	}

	.donut__sub {
		color: var(--tw-muted);
		font-size: 11px;
	}

	.donut__track {
		stroke: color-mix(in srgb, var(--tw-text) 8%, transparent);
	}

	.donut__legend {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 7px;
		min-width: 130px;
	}

	.donut__legend li {
		display: grid;
		grid-template-columns: 12px 1fr auto;
		align-items: center;
		gap: 8px;
		font-size: 13px;
	}

	.donut__swatch {
		width: 12px;
		height: 12px;
		border-radius: 2px;
	}

	.donut__name {
		color: var(--tw-muted);
	}

	.donut__pct {
		font-weight: 700;
	}
</style>
