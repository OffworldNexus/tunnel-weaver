<script lang="ts">
	/**
	 * Security (Figma "10 / Security"), under the signed-in shell.
	 *
	 * Only the Password panel is in scope for WVR-50: passkeys, two-factor
	 * authentication and connected providers belong to other stories, and the
	 * design file's own contract places "active sessions" out of scope — so there
	 * is no session list here, only the entry point to changing the password.
	 */
	import { me } from '#lib/app/me';
	import { href } from '#lib/app/paths';
	import Keycap from '#lib/ui/Keycap.svelte';
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

	<Keycap href={href('/app/security/password')} variant="ghost">Change password</Keycap>
</section>

<style lang="scss">
	/* The page rhythm measured off the frame: a 16px gap between the lede and
	   the panels. */
	.lede {
		margin-top: 16px;
	}

	/* A panel on the page surface, mirroring the drawn "Panel / Password":
	   25px of inner padding, a 24px heading, and 16px between the heading, the
	   state line and the action. */
	.panel {
		margin-top: 16px;
		padding: 25px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
	}

	.panel h2 {
		margin: 0;
		font-size: 24px;
		line-height: 32px;
	}

	.state {
		margin: 16px 0 0;
		color: var(--tw-muted);
		font-size: 16px;
	}

	.check {
		color: var(--tw-success);
		font-weight: 700;
	}

	/* The action is a full-width "key" keycap (Figma `key`/`onKey`), not the
	   page-surface ghost: a mode-invariant dark cap with light text. */
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
