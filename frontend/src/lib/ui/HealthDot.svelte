<script lang="ts">
	/** A coloured presence dot, optionally with its label. */
	interface Props {
		online?: boolean;
		showLabel?: boolean;
		pulse?: boolean;
	}

	let { online = false, showLabel = true, pulse = true }: Props = $props();

	const label = $derived(online ? 'Online' : 'Offline');
	const color = $derived(online ? 'var(--tw-online)' : 'var(--tw-offline)');
</script>

<span class="dot-wrap" style="--dot-color: {color}">
	<span class="dot" class:pulse={pulse && online} role="img" aria-label={label}></span>
	{#if showLabel}<span class="dot-label">{label}</span>{/if}
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
