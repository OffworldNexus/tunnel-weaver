<script lang="ts">
	import { useSession } from '#lib/app/session.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { resolve } from '$app/paths';

	import { REPO_URL } from './repo';

	const session = useSession();
</script>

<!-- Closing CTA: repeat the primary action at the end of the page. -->
<section class="closing">
	<div class="closing__panel">
		<h2 class="closing__title">Ready to open a tunnel?</h2>
		<p class="closing__text">
			{#if session.user}
				Your machines, tunnels and traffic are waiting in the console.
			{:else}
				Create an account, verify your email, and your first hostname is a few minutes away.
			{/if}
		</p>
		<div class="closing__actions">
			{#if session.user}
				<Keycap href={resolve('/app')}>Open your console</Keycap>
			{:else}
				<Keycap href={resolve('/(auth)/sign-up')}>Create account</Keycap>
				<Keycap variant="ghost" href={resolve('/(auth)/sign-in')}>Sign in</Keycap>
			{/if}
			<Keycap variant="ghost" href={REPO_URL} target="_blank" rel="noopener noreferrer">
				<span class="closing__cta"><Icon name="github" />Get on GitHub</span>
			</Keycap>
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

	/* Icon + label inside the GitHub keycap; the snippet contents are compiled here,
	   so this wrapper is in this component's scope. */
	.closing__cta {
		display: inline-flex;
		align-items: center;
		gap: 8px;
	}

	/* The Icon component sets its own 24px size, which would outweigh the label;
	   the extra `.closing__cta` class keeps this override specific enough. */
	.closing__cta :global(svg) {
		width: 20px;
		height: 20px;
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
