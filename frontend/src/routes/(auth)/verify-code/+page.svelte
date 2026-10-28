<script lang="ts">
	/**
	 * The second-factor step of a sign-in (WVR-167, WVR-166).
	 *
	 * The password step opens a session that can do nothing but be here: the
	 * relay refuses every other account endpoint until a second factor is
	 * accepted, and this page's only route onwards is `login/verify` (the emailed
	 * code) or `login/totp` (the code an authenticator app shows).
	 *
	 * Which one it asks for is not decided here: the relay names the ways up from
	 * the session's level on the stream, strongest first, and this page performs
	 * the first. An account with a confirmed authenticator app is therefore asked
	 * for the app's code, with the emailed code behind the button below. The page
	 * asks the relay for nothing on arrival — in particular, no second email is
	 * sent: an account with an app gets no code mailed at sign-in at all, and the
	 * button below is what asks for one.
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
	import { climb } from '#lib/app/upgrade';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	const session = useSession();

	/** Which second factor this page is asking for. */
	type Factor = 'app' | 'email';

	/**
	 * What the relay is offering: the first way up to `strong` names it, and it is
	 * the relay's own answer, so it holds on a reload as well.
	 */
	const offered = $derived<Factor>(
		session.pathsTo('strong')[0]?.[0]?.step === 'verify_totp' ? 'app' : 'email'
	);

	/** The factor the person has switched to, if they have. */
	let switched = $state<Factor | null>(null);
	const asking = $derived<Factor>(switched ?? offered);

	let resending = $state(false);
	let startingOver = $state(false);
	let resent = $state('');

	const sf = jsonForm(verifyCodeSchema, { code: '' }, async (values) => {
		const res = await api(
			'POST',
			asking === 'app' ? '/api/account/login/totp' : '/api/account/login/verify',
			values,
			climb
		);
		if (res.refused) {
			return;
		}
		if (!res.ok) {
			return res.error ?? 'That code was not accepted. Try again.';
		}
		// The stream reports the new level on its own; move on once it has, so
		// the console's guard does not see the old one.
		await session.reached('strong');
		await goto(resolve(pairing.load().detour ? '/pair' : '/app'));
	});

	const { form, errors, message, submitting, enhance } = sf;

	/**
	 * Asks the relay to email a code.
	 *
	 * On a session whose offered factor is the app this is how the alternative is
	 * chosen — nothing was mailed at sign-in, so there is nothing to re-send — and
	 * on one without an app it is the ordinary re-send. Either way the page asks
	 * for the emailed code from here on, including when the relay answers
	 * `cooldown`: that means a code was issued moments ago, which is exactly the
	 * case where the one the person already has is the one to type.
	 */
	async function resend(): Promise<void> {
		resending = true;
		resent = '';
		const res = await api<{ status: string }>('POST', '/api/account/login/resend', {}, climb);
		resending = false;
		if (res.refused) {
			return;
		}
		switched = 'email';
		if (!res.ok) {
			resent = res.error ?? 'We could not send a new code. Try again.';
			return;
		}
		resent =
			res.data?.status === 'cooldown'
				? 'A code was just sent. Enter the last one you received.'
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
		// Leaving either way: a refusal here means the session is already gone.
		await api('POST', '/api/account/logout', {}, () => {});
		session.stop();
		// A full load, like the other session-ending flows: it keeps the router
		// from reading a session that was just retired.
		window.location.assign(resolve('/(auth)/sign-in'));
	}
</script>

<svelte:head>
	<title>Enter your code · Tunnel Weaver</title>
</svelte:head>

{#if session.level === 'basic'}
	<Page labelledby="verify-code-title">
		<h1 id="verify-code-title">Enter your code</h1>
		{#if asking === 'app'}
			<p class="lede">
				Enter the six-digit code your authenticator app shows for
				<strong>{session.user?.email || 'your account'}</strong>.
			</p>
		{:else}
			<p class="lede">
				We emailed a six-digit code to
				<strong>{session.user?.email || 'your address'}</strong>.
			</p>
		{/if}

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
				{asking === 'app' ? 'Email me a code instead' : 'Send a new code'}
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
