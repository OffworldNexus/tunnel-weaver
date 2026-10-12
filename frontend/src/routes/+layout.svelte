<script lang="ts">
	import '../styles/global.scss';
	import { config, ensureConfig } from '#lib/account/config';
	import Toaster from '#lib/ui/Toaster.svelte';

	// Warm the constants endpoint as soon as the shell mounts.
	ensureConfig().catch(() => {
		// Page-level components report a network failure with a retry path.
	});
</script>

<svelte:head>
	{#if $config}
		<link rel="stylesheet" href={`${$config.altcha_assets_base}altcha.css`} />
	{/if}
</svelte:head>

<a class="skip-link" href="#main">Skip to content</a>
<Toaster />

<slot />

<style lang="scss">
	.skip-link {
		position: absolute;
		left: 50%;
		top: -60px;
		transform: translateX(-50%);
		z-index: 30;
		padding: 10px 16px;
		border-radius: 0 0 var(--tw-radius) var(--tw-radius);
		background: var(--tw-text);
		color: var(--tw-deck);
		text-decoration: none;
		transition: top 120ms ease;
	}

	.skip-link:focus {
		top: 0;
	}

	@media (prefers-reduced-motion: reduce) {
		.skip-link {
			transition: none;
		}
	}
</style>
