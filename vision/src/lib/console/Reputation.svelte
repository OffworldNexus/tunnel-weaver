<script lang="ts">
	/** A 0–100 reputation score: a meter plus the number. */
	import Icon from '#lib/ui/Icon.svelte';

	import { reputationColor, reputationLabel } from './palette';

	export let score: number;
	export let compact = false;
	export let showLabel = false;

	$: color = reputationColor(score);
	$: label = reputationLabel(score);
</script>

<span class="rep" style="--rep-color: {color}" class:compact title="{score}/100 · {label}">
	{#if showLabel}
		<span class="rep__flag" aria-hidden="true"><Icon name="shield" size={15} /></span>
	{/if}
	<span class="rep__meter" role="img" aria-label="Reputation {score} of 100">
		<span class="rep__fill" style="width: {Math.max(3, score)}%"></span>
	</span>
	<span class="rep__score mono">{score}</span>
	{#if showLabel}<span class="rep__label">{label}</span>{/if}
</span>

<style lang="scss">
	.rep {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		font-size: 13px;
	}

	.rep__flag {
		color: var(--rep-color);
	}

	.rep__meter {
		position: relative;
		width: 72px;
		height: 6px;
		border-radius: 999px;
		background: color-mix(in srgb, var(--tw-text) 10%, transparent);
		overflow: hidden;
	}

	.compact .rep__meter {
		width: 46px;
	}

	.rep__fill {
		display: block;
		height: 100%;
		border-radius: 999px;
		background: var(--rep-color);
	}

	.rep__score {
		font-weight: 700;
		color: var(--rep-color);
	}

	.rep__label {
		color: var(--tw-muted);
	}
</style>
