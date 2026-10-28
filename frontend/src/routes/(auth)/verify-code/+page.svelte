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
	 * for the app's code, and "Try another way" hands off to the chooser
	 * (`/(auth)/another-way`) for everything else the account can do — which is
	 * where the emailed code lives, because it only reaches the person once it has
	 * been asked for. The page asks the relay for nothing on arrival: an account
	 * with an app gets no code mailed at sign-in at all.
	 *
	 * Once accepted, the session is finished and the person continues to the
	 * console — or back to a pending `/pair` detour, which is why the detour flag
	 * is read here rather than at the password step.
	 */
	import { api } from '#lib/account/api';
	import { jsonForm } from '#lib/account/form';
	import { verifyCodeSchema } from '#lib/account/schemas';
	import { flow, pairing } from '#lib/account/state';
	import { useSession } from '#lib/app/session.svelte';
	import { climb } from '#lib/app/upgrade';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	const session = useSession();

	/** Which second factor this page is asking for. */
	type Factor = 'app' | 'email';

	/**
	 * What the relay is offering *as a second factor*: the first way up that is a
	 * code to enter, in the relay's own preference order.
	 *
	 * A passkey is deliberately not chosen here. It is a way *in* — offered on the
	 * sign-in page, and in the chooser whenever the relay lists it — and someone
	 * who has typed a password and landed on this step is finishing what they
	 * started rather than reaching for a different way in. The emailed code is the
	 * fallback because every account has one.
	 */
	const offered = $derived<Factor>(
		session
			.pathsTo('strong')
			.map((option) => option[0]?.step)
			.find((step) => step === 'verify_totp' || step === 'verify_email_otp') === 'verify_totp'
			? 'app'
			: 'email'
	);

	/**
	 * The factor the chooser ("try another way") sent the person here for, read
	 * once as the page mounts. It is cleared only when a code is accepted, so a
	 * reload of this step keeps the choice while the *next* sign-in starts on
	 * whatever the relay offers.
	 */
	function chosenFactor(): Factor | null {
		const chosen = flow.load().second_factor;
		return chosen === 'app' || chosen === 'email' ? chosen : null;
	}
	const chosen = chosenFactor();

	/**
	 * Whether the chooser is worth offering at all — there has to be something to
	 * choose. With a single way up (the emailed code, on an account with no app)
	 * it would only list the factor the page is already asking for.
	 */
	const hasAlternatives = $derived(session.pathsTo('strong').length > 1);

	/** The factor a local action switched to (asking for a fresh emailed code). */
	let switched = $state<Factor | null>(null);

	/** What the page asks for: this page's own action first, then the chooser, then the relay. */
	const asking = $derived<Factor>(switched ?? chosen ?? offered);

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
		// The chosen factor has been used: the next sign-in in this tab starts on
		// what the relay offers rather than on last time's choice.
		flow.save({ second_factor: '' });
		// The stream reports the new level on its own; move on once it has, so
		// the console's guard does not see the old one.
		await session.reached('strong');
		await goto(resolve(pairing.load().detour ? '/pair' : '/app'));
	});

	const { form, errors, message, submitting, enhance } = sf;

	/**
	 * Asks the relay to email a fresh code.
	 *
	 * The way *into* the emailed factor is the chooser ("try another way"), which
	 * sends one when it is picked; this is the re-send for someone already on that
	 * view whose code is old or lost. Either way the person stays on the emailed
	 * code, including when the relay answers `cooldown`: that means a code was
	 * issued moments ago, which is exactly the case where the one they already
	 * have is the one to type.
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
		// The chosen factor goes with the session: the next sign-in starts on what
		// the relay offers rather than on this attempt's choice.
		flow.save({ second_factor: '' });
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

		<!--
			Where the code is coming from, before anything asks for it. The source
			is the whole difference between the two states — open an app, or open a
			mailbox — and the field below reads exactly the same either way. The
			name is a chip so it reads as a label rather than as more prose, and the
			detail is what the field is described by.
		-->
		<div class="source">
			<span class="source__icon" aria-hidden="true">
				<Icon name={asking === 'app' ? 'shield' : 'inbox'} size={20} />
			</span>
			<div class="source__copy">
				<span class="source__name">{asking === 'app' ? 'Authenticator app' : 'Email'}</span>
				{#if asking === 'app'}
					<p class="source__detail" id="code-source">
						Enter the six-digit code your authenticator app shows for
						<strong>{session.user?.email || 'your account'}</strong>.
					</p>
				{:else}
					<p class="source__detail" id="code-source">
						We emailed a six-digit code to
						<strong>{session.user?.email || 'your address'}</strong>.
					</p>
				{/if}
			</div>
		</div>

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
					aria-describedby={$errors.code ? 'code-source code-error' : 'code-source'}
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
			{#if asking === 'email'}
				<Keycap type="button" variant="ghost" onclick={resend} loading={resending}>
					Send a new code
				</Keycap>
			{/if}
			{#if hasAlternatives}
				<Keycap href={resolve('/(auth)/another-way')} variant="ghost">Try another way</Keycap>
			{/if}
			<Keycap type="button" variant="ghost" onclick={startOver} loading={startingOver}>
				Start over
			</Keycap>
		</div>
		{#if resent}<p class="hint resent" role="status">{resent}</p>{/if}
	</Page>
{/if}

<style lang="scss">
	/* Where the code is coming from. One card, because the source is the whole
	   difference between the two states: a person sent to their authenticator app
	   and a person sent to their mailbox are doing different things, and the field
	   under them is identical. */
	.source {
		display: flex;
		align-items: flex-start;
		gap: 12px;
		margin-top: 16px;
		padding: 14px 16px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-deck);
	}

	.source__icon {
		flex: none;
		display: flex;
		margin-top: 2px;
		color: var(--tw-muted);
	}

	.source__copy {
		display: flex;
		flex-direction: column;
		gap: 6px;
		min-width: 0;
	}

	/* The chip is the label; the sentence under it is what the field is described
	   by, so a screen reader hears where the code comes from as it reaches the
	   input. */
	.source__name {
		align-self: flex-start;
		padding: 1px 9px;
		border: 1.5px solid currentColor;
		border-radius: 999px;
		font-size: 11px;
		font-weight: 700;
		letter-spacing: 1.2px;
		text-transform: uppercase;
	}

	.source__detail {
		margin: 0;
		color: var(--tw-muted);
		font-size: 15px;
		line-height: 1.5;
	}

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
