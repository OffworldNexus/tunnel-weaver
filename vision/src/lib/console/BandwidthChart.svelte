<script lang="ts">
	/**
	 * Real-time speed graph (in `/s`), stacked in/out, with:
	 * - `@ark-ui/svelte` date range picker (defaults to real-time floating 3h
	 *   over 1-minute buckets)
	 * - videotex metric selector (`External`, `Tunnel`, `Total`, `Requests`)
	 * - 30-day `P50` and `P95` reference lines.
	 */
	import type { Machine } from '#lib/mock/types';
	import { bytes } from '#lib/mock/format';

	import AreaChart from './AreaChart.svelte';
	import type { RangePreset } from './chart';
	import DateRangePicker from './DateRangePicker.svelte';
	import Panel from './Panel.svelte';
	import { machineSeries, synthesiseRange } from './series';

	export let machines: Machine[] = [];
	export let title = 'Real-time bandwidth';
	export let subtitle = 'Minute-by-minute series';
	export let height = 250;

	type Metric = 'external' | 'tunnel' | 'total' | 'requests';
	let metric: Metric = 'external';

	let preset: RangePreset = '3h';
	let customStartMs = 0;
	let customEndMs = 0;
	let rangeLabel = 'Live · 3h';

	$: basePoints = machineSeries(machines);

	$: windowedPoints = (() => {
		if (preset === '1h') {
			return basePoints.slice(-60);
		}
		if (preset === '3h') {
			return basePoints.slice(-180);
		}
		if (preset === '24h') {
			const now = basePoints.at(-1)?.ts ?? Date.now();
			return synthesiseRange(basePoints, now - 24 * 3_600_000, now);
		}
		if (preset === '7d') {
			const now = basePoints.at(-1)?.ts ?? Date.now();
			return synthesiseRange(basePoints, now - 7 * 24 * 3_600_000, now);
		}
		return synthesiseRange(basePoints, customStartMs, customEndMs);
	})();

	$: times = windowedPoints.map((p) => p.ts);

	// Convert 1-minute bucket sums into per-second rates (`value / 60`).
	$: extIn = windowedPoints.map((p) => p.bytesIn / 60);
	$: extOut = windowedPoints.map((p) => p.bytesOut / 60);
	$: tunIn = windowedPoints.map((p) => p.tunIn / 60);
	$: tunOut = windowedPoints.map((p) => p.tunOut / 60);
	$: totIn = windowedPoints.map((p) => (p.bytesIn + p.tunIn) / 60);
	$: totOut = windowedPoints.map((p) => (p.bytesOut + p.tunOut) / 60);
	$: reqRate = windowedPoints.map((p) => p.requests / 60);

	$: series =
		metric === 'requests'
			? [{ label: 'Requests', color: 'var(--tw-c3)', points: reqRate }]
			: metric === 'tunnel'
				? [
						{ label: 'Out (mux)', color: 'var(--tw-c5)', points: tunOut },
						{ label: 'In (mux)', color: 'var(--tw-c6)', points: tunIn }
					]
				: metric === 'total'
					? [
							{ label: 'Out (total)', color: 'var(--tw-c1)', points: totOut },
							{ label: 'In (total)', color: 'var(--tw-c2)', points: totIn }
						]
					: [
							{ label: 'Out (external)', color: 'var(--tw-c1)', points: extOut },
							{ label: 'In (external)', color: 'var(--tw-c2)', points: extIn }
						];

	$: stacked = metric !== 'requests';

	function formatSpeed(valPerSec: number): string {
		if (metric === 'requests') {
			if (valPerSec >= 100) {
				return `${Math.round(valPerSec)} req/s`;
			}
			return `${valPerSec.toFixed(1)} req/s`;
		}
		return `${bytes(valPerSec)}/s`;
	}

	/**
	 * 30-day P50 and P95 reference rates (in `/s`), computed from the baseline
	 * distribution of `basePoints` so they remain stable as new minutes arrive
	 * or when the date window changes.
	 */
	$: percentiles = (() => {
		if (basePoints.length === 0) {
			return { p50: 0, p95: 0 };
		}
		const totalsPerSec = basePoints
			.map((p) => {
				if (metric === 'requests') {
					return p.requests / 60;
				}
				if (metric === 'tunnel') {
					return (p.tunOut + p.tunIn) / 60;
				}
				if (metric === 'total') {
					return (p.bytesOut + p.bytesIn + p.tunOut + p.tunIn) / 60;
				}
				return (p.bytesOut + p.bytesIn) / 60;
			})
			.sort((a, b) => a - b);

		const idx50 = Math.floor(totalsPerSec.length * 0.5);
		const idx95 = Math.min(totalsPerSec.length - 1, Math.floor(totalsPerSec.length * 0.95));
		return {
			p50: totalsPerSec[idx50] ?? 0,
			p95: totalsPerSec[idx95] ?? 0
		};
	})();

	$: currentRate = (() => {
		const lastIdx = windowedPoints.length - 1;
		if (lastIdx < 0) {
			return '—';
		}
		const val = series.reduce((sum, s) => sum + (s.points[lastIdx] ?? 0), 0);
		return formatSpeed(val);
	})();

	const metrics: { key: Metric; label: string }[] = [
		{ key: 'external', label: 'External' },
		{ key: 'tunnel', label: 'Tunnel' },
		{ key: 'total', label: 'Total' },
		{ key: 'requests', label: 'Requests' }
	];
</script>

<Panel {title} subtitle="{subtitle} · {rangeLabel} · now {currentRate}">
	<svelte:fragment slot="actions">
		<div class="bw-controls">
			<DateRangePicker
				bind:preset
				bind:customStartMs
				bind:customEndMs
				onChange={(next) => {
					preset = next.preset;
					customStartMs = next.startMs;
					customEndMs = next.endMs;
					rangeLabel = next.label;
				}}
			/>
			<div class="chips" role="radiogroup" aria-label="Bandwidth metric">
				{#each metrics as m (m.key)}
					<button
						class="chip"
						class:is-on={metric === m.key}
						type="button"
						aria-pressed={metric === m.key}
						on:click={() => (metric = m.key)}
					>
						{m.label}
					</button>
				{/each}
			</div>
		</div>
	</svelte:fragment>
	<AreaChart
		{series}
		{times}
		format={formatSpeed}
		yFormat={formatSpeed}
		{height}
		{stacked}
		p50={percentiles.p50}
		p95={percentiles.p95}
	/>
</Panel>

<style lang="scss">
	.bw-controls {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: flex-end;
		gap: 8px;
	}
</style>
