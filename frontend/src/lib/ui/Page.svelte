<script lang="ts">
	import type { Snippet } from 'svelte';

	import Brand from '#lib/brand/Brand.svelte';
	import SiteFooter from '#lib/ui/SiteFooter.svelte';

	interface Props {
		/** Centre the brand; account pages do, and the holding page does too. */
		center?: boolean;
		/** id of the page's `<h1>`, wired to `<main aria-labelledby>`. */
		labelledby?: string;
		children?: Snippet;
	}

	let { center = true, labelledby = undefined, children }: Props = $props();
</script>

<!-- The account-plane page shell: brand header, a centred column, footer. -->
<div class="page">
	<Brand {center} />
	<main id="main" class="column" aria-labelledby={labelledby}>
		{@render children?.()}
	</main>
	<SiteFooter />
</div>

<style lang="scss">
	.page {
		width: 100%;
		/* 100vh × 100vw landing / account shell. */
		min-height: 100svh;
		display: flex;
		flex-direction: column;
		align-items: center;
		gap: clamp(28px, 5vh, 48px);
		padding: clamp(28px, 6vh, 56px) 20px 0;
	}

	/* The readable measure shared by every account page. */
	.column {
		width: 100%;
		max-width: 416px;
	}

	/* mobile: ≤640px */
	@media (max-width: 640px) {
		.page {
			padding-top: 24px;
		}
	}

	/* tablet: 641–1023px */
	@media (min-width: 641px) and (max-width: 1023px) {
		.page {
			padding-top: clamp(36px, 7vh, 64px);
		}
	}

	/* desktop: ≥1024px */
	@media (min-width: 1024px) {
		.page {
			gap: clamp(36px, 6vh, 56px);
		}
	}
</style>
