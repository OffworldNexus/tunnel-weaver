<script lang="ts">
	/**
	 * High-precision time-series speed chart powered by `layerchart`.
	 *
	 * - Plots per-second rates (`B/s`, `KB/s`, `MB/s`, `req/s`) over minute-by-minute
	 *   buckets at 1:1 device coordinates (no stretched `viewBox`).
	 * - Draws 30-day `P50` and `P95` reference lines so current traffic can be
	 *   read against typical and peak 30-day baselines.
	 * - Locks the y-domain ceiling to a quantized step above `P95` and the window
	 *   peak so the vertical scale stays stable.
	 * - Smoothly slides new minute buckets in from the right when `minutePulse`
	 *   ticks.
	 */
	import { scaleTime } from 'd3-scale';
	import { curveMonotoneX } from 'd3-shape';
	import { AreaChart as LcAreaChart } from 'layerchart';

	import { minutePulse } from '#lib/mock/store';

	import type { ChartSeries } from './chart';

	export let series: ChartSeries[] = [];
	export let times: number[] = [];
	export let height = 240;
	export let format: (n: number) => string = (n) => String(Math.round(n));
	export let yFormat: (n: number) => string = format;
	export let stacked = false;
	/** 30-day median rate (in the same `/s` unit as `series`). */
	export let p50 = 0;
	/** 30-day 95th-percentile rate (in the same `/s` unit as `series`). */
	export let p95 = 0;

	$: n = Math.min(times.length, ...(series.length ? series.map((s) => s.points.length) : [0]));

	$: rows = Array.from({ length: n }, (_, i) => {
		const row: Record<string, unknown> = {
			date: new Date(times[i]),
			ts: times[i]
		};
		let sum = 0;
		for (let si = 0; si < series.length; si += 1) {
			const val = series[si].points[i] ?? 0;
			row[`s${si}`] = val;
			sum += val;
		}
		row.total = sum;
		return row;
	});

	$: lcSeries = series.map((ser, i) => ({
		key: `s${i}`,
		label: ser.label,
		color: ser.color
	}));

	$: windowMax = rows.reduce((max, r) => {
		if (stacked) {
			return Math.max(max, Number(r.total ?? 0));
		}
		let m = max;
		for (let si = 0; si < series.length; si += 1) {
			m = Math.max(m, Number(r[`s${si}`] ?? 0));
		}
		return m;
	}, 0);

	/**
	 * Quantize the y-axis ceiling to a clean step above `Math.max(p95 * 1.25, windowMax * 1.1)`
	 * so minor minute-to-minute fluctuations never make the axis jump.
	 */
	function stableCeiling(raw: number): number {
		if (raw <= 0) {
			return 10;
		}
		const mag = 10 ** Math.floor(Math.log10(raw));
		const norm = raw / mag;
		const step =
			norm <= 1.2
				? 1.2
				: norm <= 1.5
					? 1.5
					: norm <= 2
						? 2
						: norm <= 2.5
							? 2.5
							: norm <= 3
								? 3
								: norm <= 4
									? 4
									: norm <= 5
										? 5
										: norm <= 6
											? 6
											: norm <= 8
												? 8
												: 10;
		return step * mag;
	}

	$: yMax = stableCeiling(Math.max(p95 * 1.25, windowMax * 1.12, 1));

	$: spanMs = n >= 2 ? times[n - 1] - times[0] : 0;

	function formatTimeTick(d: Date): string {
		if (spanMs > 36 * 3_600_000) {
			return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
		}
		return d.toLocaleTimeString(undefined, {
			hour: '2-digit',
			minute: '2-digit',
			hour12: false
		});
	}

	$: annotations = [
		...(p95 > 0
			? [
					{
						type: 'line' as const,
						y: p95,
						label: `30d P95 · ${format(p95)}`,
						labelPlacement: 'top-right' as const,
						labelYOffset: 4,
						labelXOffset: -8,
						props: {
							line: { class: 'lc-ref-line lc-ref-line--p95' },
							label: { class: 'lc-ref-text lc-ref-text--p95' }
						}
					}
				]
			: []),
		...(p50 > 0
			? [
					{
						type: 'line' as const,
						y: p50,
						label: `30d P50 · ${format(p50)}`,
						labelPlacement: 'top-right' as const,
						labelYOffset: 4,
						labelXOffset: -8,
						props: {
							line: { class: 'lc-ref-line lc-ref-line--p50' },
							label: { class: 'lc-ref-text lc-ref-text--p50' }
						}
					}
				]
			: [])
	];

	$: latestTotal = Number(rows.at(-1)?.total ?? 0);

	// Trigger a smooth slide-in pulse whenever a new minute bucket rolls in.
	let sliding = false;
	let lastPulse = $minutePulse;
	$: if ($minutePulse !== lastPulse) {
		lastPulse = $minutePulse;
		sliding = true;
		setTimeout(() => {
			sliding = false;
		}, 620);
	}
</script>

<div class="lc-wrap" style="--chart-h: {height}px; --buckets: {Math.max(20, n)}">
	<div class="lc-legend">
		{#each series as ser (ser.label)}
			<span class="lc-legend__item">
				<span class="lc-legend__swatch" style="background: {ser.color}"></span>
				<span class="lc-legend__label">{ser.label}</span>
				<span class="lc-legend__val mono">{format(ser.points.at(-1) ?? 0)}</span>
			</span>
		{/each}
		{#if stacked && series.length > 1}
			<span class="lc-legend__item lc-legend__item--sep">
				<span class="lc-legend__label">Combined</span>
				<span class="lc-legend__val mono">{format(latestTotal)}</span>
			</span>
		{/if}
		{#if p50 > 0}
			<span class="lc-legend__item lc-legend__item--sep">
				<span class="lc-legend__rule lc-legend__rule--p50"></span>
				<span class="lc-legend__label">30d P50</span>
				<span class="lc-legend__val mono">{format(p50)}</span>
			</span>
		{/if}
		{#if p95 > 0}
			<span class="lc-legend__item">
				<span class="lc-legend__rule lc-legend__rule--p95"></span>
				<span class="lc-legend__label">30d P95</span>
				<span class="lc-legend__val mono">{format(p95)}</span>
			</span>
		{/if}
	</div>

	<div class="lc-stage" class:is-sliding={sliding}>
		{#if rows.length > 1}
			<LcAreaChart
				data={rows}
				x="date"
				xScale={scaleTime()}
				yDomain={[0, yMax]}
				yNice={false}
				series={lcSeries}
				seriesLayout={stacked && series.length > 1 ? 'stack' : 'overlap'}
				padding={{ top: 14, right: 14, bottom: 34, left: 68 }}
				{annotations}
				props={{
					area: {
						curve: curveMonotoneX,
						fillOpacity: 0.34,
						line: { strokeWidth: 1.75 }
					},
					grid: {
						x: true,
						y: true
					},
					xAxis: {
						ticks: 7,
						tickLength: 4,
						format: formatTimeTick
					},
					yAxis: {
						ticks: 5,
						tickLength: 4,
						format: (v: number) => yFormat(v)
					}
				}}
			/>
		{/if}
	</div>
</div>

<style lang="scss">
	.lc-wrap {
		display: flex;
		flex-direction: column;
		gap: 10px;
		min-width: 0;
		--color-surface-content: var(--tw-muted);
		--color-surface-100: var(--tw-well);
		--color-surface-300: var(--tw-well);
	}

	.lc-legend {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 8px 18px;
		font-size: 12px;
	}

	.lc-legend__item {
		display: inline-flex;
		align-items: center;
		gap: 7px;
	}

	.lc-legend__item--sep {
		padding-left: 14px;
		border-left: 1px solid var(--tw-line-hair);
	}

	.lc-legend__swatch {
		width: 10px;
		height: 10px;
		border-radius: 1px;
	}

	.lc-legend__rule {
		width: 16px;
		height: 0;
		border-top: 2px dashed var(--tw-muted);
	}

	.lc-legend__rule--p50 {
		border-top-style: dotted;
		border-top-color: var(--tw-info);
	}

	.lc-legend__rule--p95 {
		border-top-style: dashed;
		border-top-color: var(--tw-accent);
	}

	.lc-legend__label {
		color: var(--tw-muted);
	}

	.lc-legend__val {
		font-weight: 700;
		color: var(--tw-text);
	}

	.lc-stage {
		position: relative;
		width: 100%;
		height: var(--chart-h, 240px);
	}

	// Smooth horizontal slide-in when a new 1-minute bucket enters on the right.
	.lc-stage.is-sliding :global(.lc-area-path),
	.lc-stage.is-sliding :global(.lc-area-line) {
		animation: minute-slide 560ms cubic-bezier(0.22, 1, 0.36, 1);
	}

	@keyframes minute-slide {
		0% {
			transform: translateX(calc(100% / var(--buckets, 60)));
		}
		100% {
			transform: translateX(0);
		}
	}

	// LayerChart SVG & tooltip styling tuned to the Minitel console palette
	.lc-stage :global(.lc-grid-x-line),
	.lc-stage :global(.lc-grid-y-line) {
		stroke: var(--tw-line-hair);
		stroke-dasharray: 2 3;
	}

	.lc-stage :global(.lc-axis-rule),
	.lc-stage :global(.lc-axis-tick) {
		stroke: var(--tw-border);
	}

	.lc-stage :global(.lc-axis-tick-label) {
		font-family: var(--tw-mono);
		font-size: 11px;
		font-weight: 500;
		fill: var(--tw-muted);
		stroke: none;
	}

	.lc-stage :global(.lc-ref-line) {
		stroke-width: 1.5;
		pointer-events: none;
	}

	.lc-stage :global(.lc-ref-line--p50) {
		stroke: var(--tw-info);
		stroke-dasharray: 2 4;
	}

	.lc-stage :global(.lc-ref-line--p95) {
		stroke: var(--tw-accent);
		stroke-dasharray: 6 4;
	}

	.lc-stage :global(.lc-ref-text) {
		font-family: var(--tw-mono);
		font-size: 11px;
		font-weight: 700;
		stroke: var(--tw-well);
		stroke-width: 3px;
		paint-order: stroke;
	}

	.lc-stage :global(.lc-ref-text--p50) {
		fill: var(--tw-info);
	}

	.lc-stage :global(.lc-ref-text--p95) {
		fill: var(--tw-accent);
	}

	.lc-stage :global(.lc-highlight-line) {
		stroke: var(--tw-accent);
		stroke-width: 1;
		stroke-dasharray: 3 3;
	}

	.lc-stage :global(.lc-tooltip-container) {
		border: 1.5px solid var(--tw-border);
		border-radius: 0;
		background: var(--tw-well);
		color: var(--tw-text);
		font-family: var(--tw-mono);
		font-size: 12px;
		box-shadow: var(--tw-shadow);
		padding: 6px 10px;
	}

	@media (prefers-reduced-motion: reduce) {
		.lc-stage.is-sliding :global(.lc-area-path),
		.lc-stage.is-sliding :global(.lc-area-line) {
			animation: none;
		}
	}
</style>
