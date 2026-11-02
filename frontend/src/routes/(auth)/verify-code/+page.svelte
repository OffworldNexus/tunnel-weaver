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
	import CodeEntry from '#lib/account/CodeEntry.svelte';
	import { flow, pairing } from '#lib/account/state';
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

	async function submit(code: string): Promise<string | void> {
		const res = await api(
			'POST',
			asking === 'app' ? '/api/account/login/totp' : '/api/account/login/verify',
			{ code },
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
	}

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

		<CodeEntry
			icon={asking === 'app' ? 'shield' : 'inbox'}
			source={asking === 'app' ? 'Authenticator app' : 'Email'}
			{submit}
			status={resent}
		>
			{#snippet detail()}
				{#if asking === 'app'}
					Enter the six-digit code your authenticator app shows for
					<strong>{session.user?.email || 'your account'}</strong>.
				{:else}
					We emailed a six-digit code to
					<strong>{session.user?.email || 'your address'}</strong>.
				{/if}
			{/snippet}
			{#snippet actions()}
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
			{/snippet}
		</CodeEntry>
	</Page>
{/if}
