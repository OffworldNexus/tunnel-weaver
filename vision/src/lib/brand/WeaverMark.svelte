<script lang="ts">
	// The flat-colour master lives next to this component and is inlined at build
	// time (`?raw`), so the mark ships as markup with no extra request and stays
	// inside the relay's strict `script-src 'self'` policy.
	import mark from './weaver-mark.svg?raw';
</script>

<!-- Decorative: the accessible name comes from the surrounding link. -->
<!-- eslint-disable-next-line svelte/no-at-html-tags -- a build-time asset from this repo, never user input -->
{@html mark}
