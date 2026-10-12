<script lang="ts">
	import { href } from '#lib/paths';
	import WeaverMark from '#lib/WeaverMark.svelte';

	/** Centre the mark + wordmark (account pages); left-align for the shell. */
	export let center = false;
</script>

<header class="brand" class:brand--center={center}>
	<a class="brand__link" href={href('/')} aria-label="Tunnel Weaver — home">
		<span class="brand__mark"><WeaverMark /></span>
		<span class="brand__word">Tunnel Weaver</span>
	</a>
</header>
