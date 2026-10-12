<script lang="ts">
	import '../styles/app.css';
	import { config, ensureConfig } from '#lib/config';
	import Notice from '#lib/Notice.svelte';

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
<Notice />

<slot />
