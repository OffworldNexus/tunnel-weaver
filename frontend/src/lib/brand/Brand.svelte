<script lang="ts">
	import WeaverMark from '#lib/brand/WeaverMark.svelte';
	import { resolve } from '$app/paths';

	interface Props {
		/** Centre the mark + wordmark (account pages); left-align for the shell. */
		center?: boolean;
	}

	let { center = false }: Props = $props();
</script>

<header class="brand" class:brand--center={center}>
	<a class="brand__link" href={resolve('/')} aria-label="Tunnel Weaver — home">
		<span class="brand__mark"><WeaverMark /></span>
		<span class="brand__word">Tunnel Weaver</span>
	</a>
</header>

<style lang="scss">
	.brand {
		display: flex;
		align-items: center;
		gap: 12px;
		width: 100%;
		max-width: 416px;
	}

	.brand--center {
		justify-content: center;
	}

	// The mark + wordmark link back to the landing page.
	.brand__link {
		display: inline-flex;
		align-items: center;
		gap: 12px;
		color: inherit;
		text-decoration: none;
		border-radius: var(--tw-radius);
		transition: opacity 120ms ease;
	}

	.brand__link:hover {
		opacity: 0.8;
		text-decoration: none;
	}

	.brand__mark {
		width: 34px;
		height: 35px;
		flex: none;
	}

	// The mark is inlined from another component, so it is not in this scope.
	.brand__mark :global(svg) {
		display: block;
		width: 100%;
		height: 100%;
	}

	.brand__word {
		font-family: var(--tw-heading);
		font-size: 20px;
		font-weight: 700;
		letter-spacing: 0.01em;
	}

	@media (prefers-reduced-motion: reduce) {
		.brand__link {
			transition: none;
		}
	}
</style>
