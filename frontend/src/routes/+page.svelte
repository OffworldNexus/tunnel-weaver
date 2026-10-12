<script lang="ts">
	/**
	 * Landing page — the product's front door.
	 *
	 * Public and stateless: an on-brand full-viewport hero (CSS-only tunnel art
	 * around the weaver mark), a "how it works" walkthrough, a benefits row and a
	 * closing call to action. Its only actions are links into the real auth
	 * routes; nothing here talks to the API.
	 */

	import { href } from '#lib/paths';
	import Brand from '#lib/Brand.svelte';
	import Icon from '#lib/Icon.svelte';
	import Keycap from '#lib/Keycap.svelte';
	import SiteFooter from '#lib/SiteFooter.svelte';
	import WeaverMark from '#lib/WeaverMark.svelte';

	// Static page copy, defined once here and mapped into the markup below.
	const steps = [
		{
			n: '01',
			title: 'Run the weaver',
			text: 'Start it next to the service you want to reach — it dials out to the relay, so nothing new is exposed on your network.'
		},
		{
			n: '02',
			title: 'Get a stable hostname',
			text: 'Your service appears at one predictable public hostname, covered by a wildcard certificate. No dynamic DNS, no rebuild on restart.'
		},
		{
			n: '03',
			title: 'Share it',
			text: 'Send the link. Traffic stays end-to-end through the relay, and the name stays the same for as long as you keep the tunnel open.'
		}
	];

	const benefits = [
		{ icon: 'plug', title: 'No port-forwarding', text: 'The weaver dials out. Keep your firewall closed.' },
		{ icon: 'lock', title: 'TLS by default', text: 'Every hostname is served over HTTPS automatically.' },
		{ icon: 'globe', title: 'One hostname per service', text: 'A flat, readable name for each thing you run.' },
		{ icon: 'battery', title: 'Batteries included', text: 'TLS, DNS, certificates and abuse protection ship with the relay — nothing extra to run.' }
	] as const;
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
		<!-- Hero: decorative CSS-only tunnel art and the primary pitch and CTAs. -->
		<section class="hero" aria-labelledby="hero-title">
			<!-- Decorative: the weaver mark ringed by rotating cut-corner frames. -->
			<div class="hero__art" aria-hidden="true">
				<span class="hero__glow"></span>
				<span class="tunnel">
					<span class="tunnel__ring"></span>
					<span class="tunnel__ring"></span>
					<span class="tunnel__ring"></span>
					<span class="tunnel__ring"></span>
					<span class="tunnel__ring"></span>
					<span class="tunnel__ring"></span>
				</span>
				<span class="hero__mark"><WeaverMark /></span>
			</div>

			<p class="hero__eyebrow">Tunnel Weaver</p>
			<h1 id="hero-title" class="hero__title">Your services, on the open web.</h1>
			<p class="hero__lede">
				Secure tunnels to the services running on your machines — reachable at a stable public
				hostname, with no port-forwarding and nothing exposed at home.
			</p>

			<div class="hero__actions">
				<Keycap wide href={href('/sign-up')}>Create account</Keycap>
				<Keycap wide variant="ghost" href={href('/sign-in')}>Sign in</Keycap>
			</div>

			<p class="hero__tagline">Small bird. Strong connections.</p>
		</section>

		<!-- How it works: the three-step narrative. -->
		<section class="section" aria-labelledby="steps-title">
			<h2 id="steps-title" class="section-title">How it works</h2>
			<p class="section-lede">Three steps from a local service to a shareable link.</p>

			<ol class="cards steps">
				{#each steps as step}
					<li class="step cut-panel">
						<span class="step__num" aria-hidden="true">{step.n}</span>
						<h3 class="step__title">{step.title}</h3>
						<p class="step__text">{step.text}</p>
					</li>
				{/each}
			</ol>
		</section>

		<!-- Why Tunnel Weaver: the supporting benefits. -->
		<section class="section" aria-labelledby="benefits-title">
			<h2 id="benefits-title" class="section-title">Why Tunnel Weaver</h2>
			<p class="section-lede">Small pieces that keep the operation boring.</p>

			<ul class="cards benefits">
				{#each benefits as benefit}
					<li class="benefit cut-panel">
						<span class="benefit__icon"><Icon name={benefit.icon} /></span>
						<div>
							<p class="benefit__title">{benefit.title}</p>
							<p class="benefit__text">{benefit.text}</p>
						</div>
					</li>
				{/each}
			</ul>
		</section>

		<!-- Closing CTA: repeat the primary action at the end of the page. -->
		<section class="closing">
			<div class="closing__panel cut-panel">
				<h2 class="closing__title">Ready to open a tunnel?</h2>
				<p class="closing__text">
					Create an account, verify your email, and your first hostname is a few minutes away.
				</p>
				<div class="closing__actions">
					<Keycap href={href('/sign-up')}>Create account</Keycap>
					<Keycap variant="ghost" href={href('/sign-in')}>Sign in</Keycap>
				</div>
			</div>
		</section>
	</main>

	<SiteFooter />
</div>
