<script lang="ts">
	/** A list of horizontal bars — "top N" breakdowns. */
	export let items: { label: string; value: number; color?: string; hint?: string }[] = [];
	export let format: (n: number) => string = (n) => String(n);
	export let max: number | undefined = undefined;

	$: peak = max ?? Math.max(1, ...items.map((i) => i.value));
</script>

<ul class="bars">
	{#each items as item (item.label)}
		<li class="bars__row">
			<span class="bars__label mono" title={item.label}>{item.label}</span>
			<span class="bars__track">
				<span
					class="bars__fill"
					style="width: {(item.value / peak) * 100}%; background: {item.color ?? 'var(--tw-c1)'}"
				></span>
			</span>
			<span class="bars__value mono">{format(item.value)}</span>
			{#if item.hint}<span class="bars__hint mono">{item.hint}</span>{/if}
		</li>
	{/each}
</ul>

<style lang="scss">
	.bars {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.bars__row {
		display: grid;
		grid-template-columns: minmax(90px, 1.3fr) minmax(80px, 2fr) auto auto;
		align-items: center;
		gap: 12px;
	}

	.bars__label {
		font-size: 13px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.bars__track {
		height: 8px;
		border-radius: 999px;
		background: color-mix(in srgb, var(--tw-text) 9%, transparent);
		overflow: hidden;
	}

	.bars__fill {
		display: block;
		height: 100%;
		border-radius: 999px;
		min-width: 2px;
	}

	.bars__value {
		font-size: 13px;
		font-weight: 700;
		text-align: right;
	}

	.bars__hint {
		color: var(--tw-muted);
		font-size: 12px;
		text-align: right;
		min-width: 52px;
	}

	@media (max-width: 520px) {
		.bars__row {
			grid-template-columns: 1fr auto;
		}

		.bars__track {
			grid-column: 1 / -1;
		}
	}
</style>
