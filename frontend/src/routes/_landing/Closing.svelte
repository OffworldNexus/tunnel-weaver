<script lang="ts">
	import Keycap from '#lib/ui/Keycap.svelte';
	import { href } from '#lib/app/paths';
</script>

<!-- Closing CTA: repeat the primary action at the end of the page. -->
<section class="closing">
	<div class="closing__panel">
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

<style lang="scss">
	@use 'mixins' as *;

	.closing {
		width: 100%;
		max-width: 1120px;
		padding: 0 clamp(20px, 5vw, 40px) clamp(44px, 9vh, 96px);
	}

	.closing__panel {
		@include cut-panel(26px, var(--tw-well));
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
		gap: 16px;
		padding: clamp(34px, 6vh, 60px) clamp(22px, 5vw, 56px);
	}

	.closing__title {
		font-size: clamp(26px, 3.4vw, 40px);
		line-height: 1.1;
	}

	.closing__text {
		max-width: 46ch;
		color: var(--tw-muted);
	}

	.closing__actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: center;
		gap: 14px;
		margin-top: 4px;
	}

	.closing__actions :global(.keycap) {
		min-width: 180px;
	}

	@media (max-width: 640px) {
		.closing__actions {
			width: 100%;
			max-width: 320px;
			flex-direction: column;
			align-items: stretch;
		}
	}
</style>
