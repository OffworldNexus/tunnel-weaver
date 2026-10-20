<script lang="ts">
	/** A coloured presence dot, optionally with its label. */
	import type { Health } from '#lib/mock/types';

	import { healthColor, healthLabel } from './palette';

	export let health: Health;
	export let showLabel = true;
	export let pulse = true;

	$: color = healthColor(health);
</script>

<span class="dot-wrap" style="--dot-color: {color}">
	<span
		class="dot"
		class:pulse={pulse && health === 'online'}
		role="img"
		aria-label={healthLabel(health)}
	></span>
	{#if showLabel}<span class="dot-label">{healthLabel(health)}</span>{/if}
</span>

<style lang="scss">
	.dot-wrap {
		display: inline-flex;
		align-items: center;
		gap: 7px;
		font-size: 13px;
	}

	.dot {
		position: relative;
		width: 9px;
		height: 9px;
		flex: none;
		border-radius: 999px;
		background: var(--dot-color);
	}

	.dot.pulse::after {
		content: '';
		position: absolute;
		inset: -4px;
		border-radius: 999px;
		border: 1.5px solid var(--dot-color);
		opacity: 0.5;
		animation: dot-ping 2.4s ease-out infinite;
	}

	.dot-label {
		color: var(--tw-muted);
	}

	@keyframes dot-ping {
		0% {
			transform: scale(0.7);
			opacity: 0.6;
		}
		70%,
		100% {
			transform: scale(1.5);
			opacity: 0;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.dot.pulse::after {
			animation: none;
		}
	}
</style>
