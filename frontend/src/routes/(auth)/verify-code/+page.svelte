<script lang="ts">
	/**
	 * The second-factor step of a sign-in (WVR-167).
	 *
	 * The password step opens a session that can do nothing but be here: the
	 * relay refuses every other account endpoint until the emailed code is
	 * accepted, and this page's only route onwards is
	 * `POST /api/account/login/verify`.
	 *
	 * Once accepted, the session is finished and the person continues to the
	 * console — or back to a pending `/pair` detour, which is why the detour flag
	 * is read here rather than at the password step.
	 */
	import { api } from '#lib/account/api';
	import { jsonForm } from '#lib/account/form';
	import { verifyCodeSchema } from '#lib/account/schemas';
	import { pairing } from '#lib/account/state';
	import { useSession } from '#lib/app/session.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const session = useSession();

	let resending = $state(false);
	let startingOver = $state(false);
	let resent = $state('');

	// The load asks for a code when this session had none in flight; say so, or
	// the person would be left wondering which of their emails is the live one.
	$effect(() => {
		if (data.codeSent) {
			resent = 'A new code is on its way.';
		}
	});

	const sf = jsonForm(verifyCodeSchema, { code: '' }, async (values) => {
		const res = await api('/api/account/login/verify', values);
		if (!res.ok) {
			return res.error ?? 'That code was not accepted. Try again.';
		}
		await goto(resolve(pairing.load().detour ? '/pair' : '/app'));
	});

	const { form, errors, message, submitting, enhance } = sf;

	/** Sends a fresh code; the relay enforces its own re-send cooldown. */
	async function resend(): Promise<void> {
		resending = true;
		resent = '';
		// `{}` so the client sends a POST; a body-less call would be a GET.
		const res = await api<{ status: string }>('/api/account/login/resend', {});
		resending = false;
		if (!res.ok) {
			resent = res.error ?? 'We could not send a new code. Try again.';
			return;
		}
		resent =
			res.data?.status === 'cooldown'
				? 'A code was just sent. Wait a moment before asking again.'
				: 'A new code is on its way.';
	}

	/**
	 * Abandons the half-signed-in session and returns to the sign-in form — the
	 * way out for someone who signed in to the wrong account. Retiring the
	 * session first is what makes the trip to `/sign-in` stick: the auth guard
	 * sends any session-holder straight back here.
	 */
	async function startOver(): Promise<void> {
		startingOver = true;
		await api('/api/account/logout', {});
		// A full load, like the other session-ending flows: it keeps the router
		// from reading a session that was just retired.
		window.location.assign(resolve('/(auth)/sign-in'));
	}
</script>

<svelte:head>
	<title>Enter your code · Tunnel Weaver</title>
</svelte:head>

{#if session.user?.auth_level === 'basic'}
	<Page labelledby="verify-code-title">
		<h1 id="verify-code-title">Enter your code</h1>
		<p class="lede">
			We emailed a six-digit code to
			<strong>{session.user.email || 'your address'}</strong>.
		</p>

		<form class="form" method="POST" use:enhance novalidate>
			<div class="field">
				<label for="code">Code</label>
				<input
					id="code"
					name="code"
					class="code"
					inputmode="numeric"
					autocomplete="one-time-code"
					autocapitalize="off"
					spellcheck="false"
					maxlength="6"
					placeholder="000000"
					bind:value={$form.code}
					disabled={$submitting}
					aria-invalid={$errors.code ? 'true' : undefined}
					aria-describedby={$errors.code ? 'code-error' : undefined}
				/>
				{#if $errors.code}<p id="code-error" class="field__error" aria-live="polite">
						{$errors.code[0]}
					</p>{/if}
			</div>

			{#if $message}
				<p class="notice-error" role="alert">{$message}</p>
			{/if}

			<Keycap type="submit" loading={$submitting} wide>
				{$submitting ? 'Checking…' : 'Continue'}
			</Keycap>
		</form>

		<div class="secondary">
			<Keycap type="button" variant="ghost" onclick={resend} loading={resending}>
				Send a new code
			</Keycap>
			<Keycap type="button" variant="ghost" onclick={startOver} loading={startingOver}>
				Start over
			</Keycap>
		</div>
		{#if resent}<p class="hint resent" role="status">{resent}</p>{/if}
	</Page>
{/if}

<style lang="scss">
	.code {
		font-family: var(--tw-mono);
		font-size: 24px;
		letter-spacing: 8px;
		text-align: center;
	}

	/* Two secondary actions on one line, sized to their labels, so neither
	   reads as a competing primary next to `Continue`. */
	.secondary {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 12px;
		margin-top: 24px;
	}

	/* Kept close to the row it reports on, rather than reading as a page caption. */
	.resent {
		margin-top: 8px;
	}
</style>
