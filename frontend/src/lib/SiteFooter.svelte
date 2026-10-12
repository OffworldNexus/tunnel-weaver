<script lang="ts">
	import { config } from '#lib/config';

	// The support address is real or absent — never invented. When the relay
	// has none configured, no contact link is rendered at all.
	$: supportEmail = $config?.support_email?.trim() || '';
</script>

<footer class="site-footer">
	<p class="site-footer__brand">
		<span class="site-footer__word">Tunnel Weaver</span>
		<span class="site-footer__tagline">Small bird. Strong connections.</span>
	</p>
	{#if supportEmail}
		<a class="site-footer__contact" href={`mailto:${supportEmail}`}>Contact</a>
	{/if}
</footer>
