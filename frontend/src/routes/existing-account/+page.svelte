<script lang="ts">
	/**
	 * "You already have an account" — the disclosure shown after verifying an
	 * email that belongs to an existing account. Deliberately reveals nothing
	 * about that account beyond its existence.
	 */

	import { loadFlow } from '#lib/flow';
	import { href } from '#lib/paths';
	import Brand from '#lib/Brand.svelte';
	import Keycap from '#lib/Keycap.svelte';
	import SiteFooter from '#lib/SiteFooter.svelte';

	// Disclose only that the address already has an account — nothing about it.
	const email = loadFlow().email ?? '';
</script>

<svelte:head>
	<title>Account found · Tunnel Weaver</title>
</svelte:head>

<div class="page">
	<Brand center />
	<main id="main" class="column" aria-labelledby="existing-title">
		<h1 id="existing-title">You already have an account</h1>

		<p class="checkbox-line"><span aria-hidden="true">✓</span> Email confirmed</p>

		<p class="lede">
			An account already exists for {#if email}<strong>{email}</strong>{:else}that address{/if}. Sign
			in to continue, or reset your password if you need a new one.
		</p>

		<div class="actions">
			<Keycap wide href={href('/sign-in')}>Sign in</Keycap>
		</div>
	</main>
	<SiteFooter />
</div>
