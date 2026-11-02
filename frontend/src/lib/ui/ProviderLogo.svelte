<script lang="ts">
	/**
	 * The logo for one identity provider, by the relay's id.
	 *
	 * The sign-in grid and the ways-up list both render providers the relay names
	 * at runtime, so this is the one place that maps an id to its mark. A provider
	 * with no drawing of its own falls back to the generic key icon rather than
	 * rendering nothing.
	 */
	import type { Component } from 'svelte';

	import Google from './Google.svelte';
	import Icon from './Icon.svelte';
	import Microsoft from './Microsoft.svelte';

	interface Props {
		/** The provider id, as the relay's config and session stream spell it. */
		id: string;
		size?: number;
	}

	let { id, size = 14 }: Props = $props();

	const LOGOS: Record<string, Component<{ size?: number }>> = {
		microsoft: Microsoft,
		google: Google
	};
</script>

{#if LOGOS[id]}
	{@const Logo = LOGOS[id]}
	<Logo {size} />
{:else}
	<Icon name="key" {size} />
{/if}
