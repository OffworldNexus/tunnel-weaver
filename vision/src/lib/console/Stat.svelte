<script lang="ts">
	/** A headline metric tile with an optional sparkline and delta. */
	import type { IconName } from '#lib/ui/icons';
	import Icon from '#lib/ui/Icon.svelte';

	import Spark from './Spark.svelte';

	export let label: string;
	export let value: string;
	export let sub = '';
	/** A ratio; positive is green, negative is red. Null hides the chip. */
	export let delta: number | null = null;
	export let color = 'var(--tw-c1)';
	export let icon: IconName | undefined = undefined;
	export let data: number[] | undefined = undefined;
</script>

<div class="stat" style="--stat-color: {color}">
	<div class="stat__top">
		<p class="stat__label">{label}</p>
		{#if icon}<span class="stat__icon"><Icon name={icon} size={18} /></span>{/if}
	</div>
	<p class="stat__value">{value}</p>
	<div class="stat__meta">
		{#if sub}<span class="stat__sub">{sub}</span>{/if}
		{#if delta !== null}
			<span class="stat__delta" class:up={delta >= 0} class:down={delta < 0}>
				<Icon name={delta >= 0 ? 'trend-up' : 'trend-down'} size={14} />
				{Math.abs(delta * 100).toFixed(1)}%
			</span>
		{/if}
	</div>
	{#if data && data.length > 1}
		<div class="stat__spark">
			<Spark {data} {color} height={30} />
		</div>
	{/if}
</div>

<style lang="scss">
	@use 'mixins' as *;

	.stat {
		@include cut-panel(12px, var(--tw-well), var(--tw-border), 1.5px);
		display: flex;
		flex-direction: column;
		gap: 6px;
		padding: 14px 16px 12px;
		min-width: 0;
	}

	.stat__top {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
	}

	.stat__label {
		font-size: 12px;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.stat__icon {
		color: var(--stat-color);
	}

	.stat__value {
		font-family: var(--tw-mono);
		font-variant-numeric: tabular-nums;
		font-size: 28px;
		font-weight: 700;
		line-height: 1.1;
		letter-spacing: -0.02em;
	}

	.stat__meta {
		display: flex;
		align-items: center;
		gap: 8px;
		min-height: 20px;
	}

	.stat__sub {
		color: var(--tw-muted);
		font-size: 13px;
	}

	.stat__delta {
		display: inline-flex;
		align-items: center;
		gap: 2px;
		font-family: var(--tw-mono);
		font-size: 12px;
		font-weight: 700;
	}

	.stat__delta.up {
		color: var(--tw-online);
	}

	.stat__delta.down {
		color: var(--tw-danger);
	}

	.stat__spark {
		height: 30px;
		margin-top: 2px;
		color: var(--stat-color);
	}
</style>
