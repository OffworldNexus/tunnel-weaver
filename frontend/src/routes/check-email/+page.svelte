<script lang="ts">
	/**
	 * "Check your email" — the hold screen between signup and verification.
	 *
	 * The pending flow id lives in session state rather than the URL, so a
	 * shared screen can't resume someone else's signup. The relay throttles
	 * resends, so the button runs a countdown seeded from the config endpoint.
	 */

	import { goto } from '$app/navigation';
	import { onDestroy, onMount } from 'svelte';
	import { superForm } from 'sveltekit-superforms';
	import { valibot } from 'sveltekit-superforms/adapters';
	import { api, messageOf } from '#lib/account/api';
	import { ensureConfig } from '#lib/account/config';
	import { clearFlow, loadFlow } from '#lib/account/flow';
	import { resendSchema } from '#lib/account/schemas';
	import { href } from '#lib/app/paths';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';

	// The flow id and address carried over from the signup just submitted.
	const carried = loadFlow();
	const flow = carried.flow ?? '';
	const email = carried.email ?? '';

	let remaining = 0;
	let info = '';
	let timer: ReturnType<typeof setInterval> | undefined;

	// Seed the resend cooldown from the relay's configured window.
	onMount(() => {
		ensureConfig()
			.then((cfg) => startCooldown(cfg.resend_cooldown_secs))
			.catch(() => {});
	});

	onDestroy(() => {
		if (timer) clearInterval(timer);
	});

	function startCooldown(seconds: number) {
		if (timer) clearInterval(timer);
		remaining = Math.max(0, Math.floor(seconds));
		timer = setInterval(() => {
			remaining = Math.max(0, remaining - 1);
			if (remaining === 0 && timer) clearInterval(timer);
		}, 1000);
	}

	// A one-field form (the hidden flow id) so the resend reuses the same
	// client-side validation, submit state and error channel as the other forms.
	const sf = superForm(
		{ flow },
		{
			validators: valibot(resendSchema),
			clearOnSubmit: 'errors-and-message',
			onSubmit: async ({ cancel }) => {
				cancel();
				const result = await sf.validateForm({ update: true });
				if (!result.valid || remaining > 0) return;
				info = '';
				try {
					const res = await api<{ status: string }>('/api/account/resend', {
						method: 'POST',
						body: { flow: result.data.flow }
					});
					if (res.ok) {
						info = 'If that address can receive mail, a fresh link is on its way.';
						const cfg = await ensureConfig().catch(() => null);
						startCooldown(cfg?.resend_cooldown_secs ?? 60);
						return;
					}
					sf.message.set(messageOf(res.data, 'We could not resend the link. Please try again.'));
				} catch {
					sf.message.set('We could not reach the server. Check your connection and try again.');
				}
			}
		}
	);

	const { form, message, submitting, enhance } = sf;

	// Abandon the pending signup and start over from a clean form.
	function useAnotherEmail() {
		clearFlow();
		goto(href('/sign-up'));
	}
</script>

<svelte:head>
	<title>Check your email · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="check-title">
	<h1 id="check-title">Check your email</h1>

	{#if flow}
		<p class="lede">Confirm your email address to continue.</p>

		<!-- Confirms where the verification mail went. -->
		<div class="panel">
			Verification sent to {#if email}<strong>{email}</strong>{:else}your address{/if}
		</div>

		<p class="lede">
			Open the email and select <strong>Verify email</strong>. Return here after confirming.
		</p>

		<form class="form" method="POST" use:enhance novalidate>
			<input type="hidden" name="flow" bind:value={$form.flow} />
			<Keycap type="submit" loading={$submitting} disabled={remaining > 0 || $submitting} wide>
				{$submitting
					? 'Resending…'
					: remaining > 0
						? `Resend in ${remaining}s`
						: 'Resend verification email'}
			</Keycap>
		</form>

		{#if info}<p class="hint" style="margin-top:16px" role="status" aria-live="polite">{info}</p>{/if}
		{#if $message}
			<p class="notice-error" role="alert" aria-live="assertive" style="margin-top:16px">{$message}</p>
		{/if}

		<p class="switch" style="margin-top:16px">
			<button type="button" class="linklike" on:click={useAnotherEmail}>Use a different email</button>
		</p>
	{:else}
		<p class="lede">This page needs a signup in progress. Start one to get a verification link.</p>
		<div class="actions">
			<Keycap wide href={href('/sign-up')}>Create an account</Keycap>
		</div>
	{/if}

	<p class="switch"><a href={href('/sign-in')}>Back to sign in</a></p>
</Page>

<style lang="scss">
	/* A recessed confirmation chip; only this route uses it. */
	.panel {
		margin-top: 24px;
		padding: 14px 16px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
		font-size: 16px;
	}
</style>
