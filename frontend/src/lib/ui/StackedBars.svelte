<script lang="ts">
	/**
	 * Horizontal stacked bars: one full-width bar per category, split into the
	 * active share and the remainder. Each row is scaled to its own total, so
	 * categories of very different sizes stay comparable.
	 */
	import type { BarGroup } from '#lib/app/chart';

	export let groups: BarGroup[] = [];
	export let activeLabel = 'Active';
	export let restLabel = 'Inactive';

	/** The active share of a group's total, as a percentage. */
	function share(group: BarGroup): number {
		return group.total > 0 ? (group.active / group.total) * 100 : 0;
	}
</script>

<div class="sbar">
	<div class="sbar__legend">
		<span class="sbar__key">
			<span class="sbar__swatch sbar__swatch--active"></span>{activeLabel}
		</span>
		<span class="sbar__key">
			<span class="sbar__swatch sbar__swatch--rest"></span>{restLabel}
		</span>
	</div>

	{#each groups as group (group.label)}
		<div class="sbar__row">
			<span class="sbar__label">{group.label}</span>
			<span
				class="sbar__track"
				role="img"
				aria-label="{group.label}: {group.active} active of {group.total}"
			>
				<span class="sbar__seg sbar__seg--active" style="width: {share(group)}%"></span>
				<span class="sbar__seg sbar__seg--rest" style="width: {100 - share(group)}%"></span>
			</span>
			<span class="sbar__value mono">
				<strong>{group.active}</strong> / {group.total}
			</span>
			<span class="sbar__pct mono">{Math.round(share(group))}%</span>
		</div>
	{/each}
</div>

<style lang="scss">
	.sbar {
		display: flex;
		flex-direction: column;
		gap: 14px;
	}

	.sbar__legend {
		display: flex;
		gap: 18px;
		font-size: 13px;
		color: var(--tw-muted);
	}

	.sbar__key {
		display: inline-flex;
		align-items: center;
		gap: 7px;
	}

	.sbar__swatch {
		width: 12px;
		height: 12px;
		border-radius: 2px;
	}

	.sbar__swatch--active {
		background: var(--tw-c2);
	}

	.sbar__swatch--rest {
		background: repeating-linear-gradient(
			-45deg,
			color-mix(in srgb, var(--tw-text) 22%, transparent) 0 3px,
			color-mix(in srgb, var(--tw-text) 10%, transparent) 3px 6px
		);
	}

	.sbar__row {
		display: grid;
		grid-template-columns: 120px 1fr 68px 42px;
		align-items: center;
		gap: 14px;
	}

	.sbar__label {
		font-size: 13px;
		font-weight: 700;
	}

	.sbar__track {
		display: flex;
		height: 22px;
		border-radius: 3px;
		overflow: hidden;
		background: color-mix(in srgb, var(--tw-text) 8%, transparent);
	}

	.sbar__seg {
		height: 100%;
		transition: width 220ms ease;
	}

	.sbar__seg--active {
		background: var(--tw-c2);
	}

	.sbar__seg--rest {
		background: repeating-linear-gradient(
			-45deg,
			color-mix(in srgb, var(--tw-text) 22%, transparent) 0 4px,
			color-mix(in srgb, var(--tw-text) 10%, transparent) 4px 8px
		);
	}

	.sbar__value {
		font-size: 14px;
		white-space: nowrap;
		text-align: right;
	}

	.sbar__value strong {
		font-size: 16px;
	}

	.sbar__pct {
		font-size: 12px;
		color: var(--tw-muted);
		text-align: right;
	}

	@media (max-width: 560px) {
		.sbar__row {
			grid-template-columns: 1fr auto;
			grid-template-areas:
				'label value'
				'track track';
			gap: 8px 14px;
		}

		.sbar__label {
			grid-area: label;
		}

		.sbar__track {
			grid-area: track;
		}

		.sbar__value {
			grid-area: value;
		}

		.sbar__pct {
			display: none;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.sbar__seg {
			transition: none;
		}
	}
</style>
