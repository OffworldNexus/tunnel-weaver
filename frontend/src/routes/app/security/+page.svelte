<script lang="ts">
	import { me } from '#lib/app/me';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { resolve } from '$app/paths';
</script>

<svelte:head>
	<title>Security · Tunnel Weaver</title>
</svelte:head>

<h1 id="app-title">Security</h1>
<p class="lede">Choose how you sign in. Protect your account.</p>

<section class="panel" aria-labelledby="password-title">
	<h2 id="password-title">Password</h2>
	{#if $me?.has_password}
		<p class="state"><span class="check" aria-hidden="true">✓</span> Password is set</p>
	{:else}
		<p class="state">No password is set</p>
	{/if}
	<Keycap href={resolve('/app/security/password')} variant="ghost">Change password</Keycap>
</section>

<style lang="scss">
	.lede {
		margin-top: 16px;
	}

	.panel {
		margin-top: 16px;
		padding: 25px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
	}

	.panel h2 {
		font-size: 24px;
		line-height: 32px;
	}

	.state {
		margin: 16px 0 0;
		color: var(--tw-muted);
	}

	.check {
		color: var(--tw-success);
		font-weight: 700;
	}

	/* A full-width dark "key" keycap rather than the page-surface ghost. */
	.panel :global(.keycap) {
		width: 100%;
		margin-top: 16px;
		color: var(--tw-on-key);
	}

	.panel :global(.keycap .keycap__face) {
		background: var(--tw-key);
	}

	.panel :global(a.keycap:hover .keycap__face) {
		background: color-mix(in srgb, var(--tw-on-key) 12%, var(--tw-key));
	}
</style>
