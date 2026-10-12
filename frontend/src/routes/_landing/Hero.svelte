<script lang="ts">
	import WeaverMark from '#lib/brand/WeaverMark.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { href } from '#lib/app/paths';
</script>

<!-- Full-viewport hero: decorative CSS-only tunnel art around the weaver mark,
     the product pitch, and the two primary CTAs. -->
<section class="hero" aria-labelledby="hero-title">
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

<style lang="scss">
	.hero {
		position: relative;
		width: 100%;
		/* A true full-viewport intro: exactly one viewport tall (with a `100vh`
		   fallback for engines without `svh`), content centred inside it. */
		min-height: 100vh;
		min-height: 100svh;
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		text-align: center;
		/* The whole block sizes against viewport *height* as well as width, so the
		   art, headline and CTAs fit inside one viewport on short screens too. The
		   extra bottom padding lifts the content slightly above dead centre so the
		   two CTAs stay comfortably above the fold. */
		gap: clamp(8px, 1.5vh, 20px);
		padding: clamp(14px, 3vh, 44px) clamp(20px, 5vw, 40px) clamp(24px, 6vh, 88px);
	}

	.hero__art {
		position: relative;
		/* Fluid brand moment: grows with both width and available height, with a
		   ceiling well above the old 220px so tall/large screens get generous art. */
		width: min(56vw, 30vh, 340px);
		aspect-ratio: 1;
		display: grid;
		place-items: center;
		margin-bottom: clamp(2px, 0.8vh, 10px);
		isolation: isolate;
	}

	/* Genuinely tall screens: let the art (and its tunnel frames) grow further. */
	@media (min-height: 900px) {
		.hero__art {
			width: min(56vw, 36vh, 440px);
		}
	}

	.hero__glow {
		position: absolute;
		inset: -26%;
		z-index: 0;
		background: radial-gradient(
			circle at 50% 50%,
			color-mix(in srgb, var(--tw-confirm) 24%, transparent),
			transparent 62%
		);
	}

	/* CSS-only tunnel: concentric cut-corner frames (the keycap motif) that drift
	   slowly, weaving around the mark. No assets, no scripts. */
	.tunnel {
		position: absolute;
		inset: 0;
		display: grid;
		place-items: center;
		animation: tunnel-weave 90s linear infinite;
	}

	.tunnel__ring {
		position: absolute;
		inset: 0;
		/* A true ring (outer shape minus an inset inner hole) so the edge follows
		   the 45° cut. A plain `border` would be clipped away on the diagonal. */
		background: var(--tw-border);
		clip-path: polygon(
			evenodd,
			0 0,
			calc(100% - 22px) 0,
			100% 22px,
			100% 100%,
			0 100%,
			1.5px 1.5px,
			calc(100% - 22.62px) 1.5px,
			calc(100% - 1.5px) 22.62px,
			calc(100% - 1.5px) calc(100% - 1.5px),
			1.5px calc(100% - 1.5px)
		);
		transform: rotate(var(--ring-rotate, 0deg)) scale(var(--ring-scale, 1));
	}

	.tunnel__ring:nth-child(1) {
		--ring-scale: 1;
		--ring-rotate: 0deg;
		opacity: 0.5;
	}

	.tunnel__ring:nth-child(2) {
		--ring-scale: 0.86;
		--ring-rotate: 12deg;
		opacity: 0.42;
	}

	.tunnel__ring:nth-child(3) {
		--ring-scale: 0.72;
		--ring-rotate: -14deg;
		opacity: 0.36;
	}

	.tunnel__ring:nth-child(4) {
		--ring-scale: 0.58;
		--ring-rotate: 22deg;
		opacity: 0.3;
	}

	.tunnel__ring:nth-child(5) {
		--ring-scale: 0.44;
		--ring-rotate: -30deg;
		opacity: 0.26;
	}

	.tunnel__ring:nth-child(6) {
		--ring-scale: 0.3;
		--ring-rotate: 40deg;
		opacity: 0.22;
	}

	.hero__mark {
		position: relative;
		z-index: 2;
		width: 42%;
		filter: drop-shadow(0 14px 30px rgb(0 0 0 / 0.35));
	}

	/* The mark is inlined from another component, so it is not in this scope. */
	.hero__mark :global(svg) {
		display: block;
		width: 100%;
		height: auto;
	}

	.hero__eyebrow {
		font-family: var(--tw-mono);
		font-size: 13px;
		letter-spacing: 0.3em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.hero__title {
		font-size: clamp(30px, 5.4vw, min(6.4vh, 60px));
		line-height: 1;
		font-weight: 700;
		letter-spacing: -0.035em;
		max-width: 15ch;
		text-wrap: balance;
	}

	.hero__lede {
		max-width: 54ch;
		color: var(--tw-muted);
		font-size: clamp(15px, 1.9vh, 19px);
		line-height: 1.55;
	}

	.hero__actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: center;
		gap: 14px;
		margin-top: 4px;
	}

	.hero__actions :global(.keycap) {
		min-width: 196px;
	}

	.hero__tagline {
		font-family: var(--tw-mono);
		font-size: 14px;
		color: var(--tw-muted);
	}

	@keyframes tunnel-weave {
		from {
			transform: rotate(0deg);
		}
		to {
			transform: rotate(360deg);
		}
	}

	/* Short viewports: shrink the art, headline and spacing a little further so the
	   whole hero — including both CTAs — still fits inside one viewport. */
	@media (max-height: 700px) {
		.hero {
			gap: clamp(6px, 1.2vh, 14px);
			padding: clamp(12px, 2.4vh, 28px) clamp(20px, 5vw, 40px) clamp(18px, 4.5vh, 48px);
		}

		.hero__art {
			width: min(40vw, 19vh, 180px);
		}

		.hero__title {
			font-size: clamp(28px, 4.8vw, min(5.8vh, 46px));
		}
	}

	@media (max-width: 640px) {
		.hero {
			/* Keep the full-viewport hero on phones too; the vh-based sizing fits it. */
			padding-top: clamp(16px, 3vh, 32px);
		}

		.hero__actions {
			width: 100%;
			max-width: 320px;
			flex-direction: column;
			align-items: stretch;
		}
	}

	@media (prefers-reduced-motion: reduce) {
		.tunnel {
			animation: none;
		}
	}
</style>
