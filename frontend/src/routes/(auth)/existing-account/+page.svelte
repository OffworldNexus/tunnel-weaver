<script lang="ts">
	/**
	 * Shown after verifying an email that already has an account. Reveals
	 * nothing about that account beyond its existence.
	 */
	import { flow } from '#lib/account/state';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { resolve } from '$app/paths';

	const { email } = flow.load();
</script>

<svelte:head>
	<title>Account found · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="existing-title">
	<h1 id="existing-title">You already have an account</h1>

	<p class="checkbox-line"><span aria-hidden="true">✓</span> Email confirmed</p>

	<p class="lede">
		An account already exists for {#if email}<strong>{email}</strong>{:else}that address{/if}. Sign
		in to continue, or <a href={resolve('/(auth)/forgot-password')}>reset your password</a> if you need
		a new one.
	</p>

	<div class="actions">
		<Keycap wide href={resolve('/(auth)/sign-in')}>Sign in</Keycap>
	</div>
</Page>

<style lang="scss">
	.checkbox-line {
		display: flex;
		align-items: center;
		gap: 8px;
		margin-top: 20px;
		color: var(--tw-success);
		font-weight: 700;
	}
</style>
