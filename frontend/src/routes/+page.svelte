<script lang="ts">
	/**
	 * Landing page — the product's front door.
	 *
	 * Public and stateless: an on-brand full-viewport hero, a "how it works"
	 * walkthrough, a benefits row and a closing call to action. Its only actions
	 * are links into the real auth routes; nothing here talks to the API. The
	 * sections are landing-only, so they live alongside this page in `_landing/`.
	 */

	import { href } from '#lib/app/paths';
	import Brand from '#lib/brand/Brand.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import SiteFooter from '#lib/ui/SiteFooter.svelte';
	import Hero from './_landing/Hero.svelte';
	import Steps from './_landing/Steps.svelte';
	import Benefits from './_landing/Benefits.svelte';
	import Closing from './_landing/Closing.svelte';
</script>

<svelte:head>
	<title>Tunnel Weaver — your services, on the open web</title>
	<meta
		name="description"
		content="Tunnel Weaver gives the services running on your machines a stable public hostname over secure tunnels — no port-forwarding, nothing exposed at home."
	/>
</svelte:head>

<div class="landing">
	<!-- Top bar: brand (links home) plus the two account entry points. -->
	<div class="landing__top">
		<Brand />
		<nav class="landing__nav" aria-label="Account">
			<a class="landing__nav-link" href={href('/sign-in')}>Sign in</a>
			<Keycap variant="ghost" href={href('/sign-up')}>Create account</Keycap>
		</nav>
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

	.landing__nav {
		display: flex;
		align-items: center;
		gap: 10px 22px;
	}

	.landing__nav-link {
		color: var(--tw-text);
		font-size: 15px;
		font-weight: 700;
	}

	.landing__nav-link:hover {
		color: var(--tw-accent);
		text-decoration: none;
	}

	@media (max-width: 640px) {
		.landing__top {
			padding: 14px 20px;
		}

		/* The CTA lives in the hero on small screens; keep the bar quiet. */
		.landing__nav :global(.keycap) {
			display: none;
		}
	}
</style>
