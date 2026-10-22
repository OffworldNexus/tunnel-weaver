<script lang="ts">
	import { config } from '#lib/account/config.svelte';

	const support = $derived(config.value?.support_email);
</script>

<footer class="site-footer">
	<p class="site-footer__brand">
		<span class="site-footer__word">Tunnel Weaver</span>
		<span class="site-footer__tagline">Small bird. Strong connections.</span>
	</p>
	{#if support}
		<a class="site-footer__contact" href={`mailto:${support}`}>Contact</a>
	{/if}
</footer>

<style lang="scss">
	.site-footer {
		width: 100%;
		margin-top: auto;
		padding: 32px 20px 24px;
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: center;
		gap: 10px 22px;
		color: var(--tw-muted);
		font-size: 14px;
	}

	.site-footer__brand {
		display: flex;
		flex-wrap: wrap;
		align-items: baseline;
		justify-content: center;
		gap: 4px 12px;
		margin: 0;
	}

	.site-footer__word {
		font-family: var(--tw-heading);
		font-weight: 700;
		color: var(--tw-text);
	}

	.site-footer__contact {
		color: var(--tw-accent);
		font-weight: 700;
	}
</style>
