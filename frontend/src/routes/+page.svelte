<script lang="ts">
	/** The public front door: static, its only actions are links. */
	import Brand from '#lib/brand/Brand.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import SiteFooter from '#lib/ui/SiteFooter.svelte';

	import Benefits from './_landing/Benefits.svelte';
	import Closing from './_landing/Closing.svelte';
	import Hero from './_landing/Hero.svelte';
	import { REPO_URL } from './_landing/repo';
	import Steps from './_landing/Steps.svelte';
</script>

<svelte:head>
	<title>Tunnel Weaver — your services, on the open web</title>
	<meta
		name="description"
		content="Tunnel Weaver gives the services running on your machines a stable public hostname over secure tunnels — no port-forwarding, nothing exposed at home."
	/>
</svelte:head>

<div class="landing">
	<!-- Top bar: brand (links home) on the left; the off-site repo link is the
	     only action in the top-right. The account CTAs live in the hero. -->
	<div class="landing__top">
		<Brand />
		<div class="landing__actions">
			<Keycap variant="ghost" href={REPO_URL} target="_blank" rel="noopener noreferrer">
				<span class="landing__github">
					<Icon name="github" />
					<span class="landing__github-label">Get on GitHub</span>
				</span>
			</Keycap>
		</div>
	</div>

	<main id="main" class="landing__main">
		<Hero />
		<Steps />
		<Benefits />
		<Closing />
	</main>

	<SiteFooter />
</div>

<style lang="scss">
	.landing {
		width: 100%;
		min-height: 100svh;
		display: flex;
		flex-direction: column;
		align-items: center;
		overflow-x: clip;
	}

	.landing__main {
		width: 100%;
		display: flex;
		flex-direction: column;
		align-items: center;
	}

	/* top bar */
	.landing__top {
		width: 100%;
		max-width: 1120px;
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
		padding: 18px clamp(20px, 5vw, 40px);
	}

	/* The brand is its own component, so it is outside this scope. */
	.landing__top :global(.brand) {
		width: auto;
		max-width: none;
	}

	/* The right-hand cluster holds only the off-site repo link; the account CTAs
	   live in the hero. */
	.landing__actions {
		display: flex;
		align-items: center;
		gap: 10px 12px;
	}

	/* Icon + label inside the GitHub keycap; the slot contents are compiled here. */
	.landing__github {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		white-space: nowrap;
	}

	/* The Icon component sets its own 24px size, which would outweigh the label;
	   the extra `.landing__github` class keeps this override specific enough. */
	.landing__github :global(svg) {
		width: 20px;
		height: 20px;
	}

	/* On narrow/medium widths the repo link collapses to just its mark, so the bar
	   never squeezes the wordmark. The label is clipped rather than removed, so
	   the link keeps its accessible name. */
	@media (max-width: 768px) {
		.landing__github-label {
			position: absolute;
			width: 1px;
			height: 1px;
			padding: 0;
			margin: -1px;
			overflow: hidden;
			clip-path: inset(50%);
			border: 0;
			white-space: nowrap;
		}

		/* A tighter cap so the icon-only control reads as a compact button. */
		.landing__actions > :global(.keycap) {
			padding: 0 14px;
		}
	}

	@media (max-width: 640px) {
		.landing__top {
			padding: 14px 20px;
			gap: 10px;
		}
	}
</style>
