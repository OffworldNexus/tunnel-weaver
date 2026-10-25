<script lang="ts">
	/**
	 * The hold screen between signup and verification. The pending flow id
	 * lives in session state rather than the URL, so a shared screen cannot
	 * resume someone else's signup. The relay throttles resends, so the button
	 * counts down its cooldown.
	 */
	import { onDestroy } from 'svelte';

	import { api } from '#lib/account/api';
	import { ensureConfig } from '#lib/account/config.svelte';
	import { flow } from '#lib/account/state';
	import { climb } from '#lib/app/upgrade';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	const carried = flow.load();

	let remaining = $state(0);
	let busy = $state(false);
	let info = $state('');
	let error = $state('');
	let timer: ReturnType<typeof setInterval> | undefined;

	async function startCooldown() {
		const cfg = await ensureConfig().catch(() => null);
		clearInterval(timer);
		remaining = cfg?.resend_cooldown_secs ?? 60;
		timer = setInterval(() => {
			remaining -= 1;
			if (remaining <= 0) {
				clearInterval(timer);
			}
		}, 1000);
	}

	void startCooldown();
	onDestroy(() => clearInterval(timer));

	async function resend() {
		busy = true;
		info = '';
		error = '';
		const res = await api('POST', '/api/account/resend', { flow: carried.flow }, climb);
		busy = false;
		if (!res.ok) {
			error = res.error ?? 'We could not resend the link. Please try again.';
			return;
		}
		info = 'If that address can receive mail, a fresh link is on its way.';
		await startCooldown();
	}

	function resendLabel(busy: boolean, remaining: number): string {
		if (busy) {
			return 'Resending…';
		}
		return remaining > 0 ? `Resend in ${remaining}s` : 'Resend verification email';
	}

	function useAnotherEmail() {
		flow.clear();
		void goto(resolve('/(auth)/sign-up'));
	}
</script>

<svelte:head>
	<title>Check your email · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="check-title">
	<h1 id="check-title">Check your email</h1>

	{#if carried.flow}
		<p class="lede">Confirm your email address to continue.</p>

		<div class="panel">Verification sent to <strong>{carried.email}</strong></div>

		<p class="lede">
			Open the email and select <strong>Verify email</strong>. Return here after confirming.
		</p>

		<div class="actions">
			<Keycap type="button" loading={busy} disabled={remaining > 0} onclick={resend} wide>
				{resendLabel(busy, remaining)}
			</Keycap>
		</div>

		{#if info}<p class="hint spaced" role="status">{info}</p>{/if}
		{#if error}<p class="notice-error spaced" role="alert">{error}</p>{/if}

		<p class="switch spaced">
			<button type="button" class="linklike" onclick={useAnotherEmail}>Use a different email</button
			>
		</p>
	{:else}
		<p class="lede">This page needs a signup in progress. Start one to get a verification link.</p>
		<div class="actions">
			<Keycap wide href={resolve('/(auth)/sign-up')}>Create an account</Keycap>
		</div>
	{/if}

	<p class="switch"><a href={resolve('/(auth)/sign-in')}>Back to sign in</a></p>
</Page>

<style lang="scss">
	.panel {
		margin-top: 24px;
		padding: 14px 16px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
	}

	.spaced {
		margin-top: 16px;
	}
</style>
