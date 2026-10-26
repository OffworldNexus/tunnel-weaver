<script lang="ts">
	import { onMount } from 'svelte';

	import Altcha from '#lib/account/Altcha.svelte';
	import { api } from '#lib/account/api';
	import EmailField from '#lib/account/EmailField.svelte';
	import { jsonForm } from '#lib/account/form';
	import { notify } from '#lib/account/notices';
	import { signInSchema } from '#lib/account/schemas';
	import { flow } from '#lib/account/state';
	import {
		failureOf,
		getAssertion,
		type PasskeyOptions,
		supported as passkeysSupported
	} from '#lib/account/webauthn';
	import { session } from '#lib/app/session.svelte';
	import { climb } from '#lib/app/upgrade';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	const carried = flow.load();
	if (carried.notice) {
		notify('success', carried.notice);
		flow.save({ notice: undefined });
	}

	let altcha = $state<{ reset(): void }>();
	let proof = $state('');
	let showPassword = $state(false);
	let passkeyBusy = $state(false);

	/** Whether this browser can run a passkey ceremony at all. */
	const passkeys = passkeysSupported();

	/**
	 * The field's discreet offer: one conditional-UI request, pending for the
	 * page's whole life so the browser can put a passkey into the focused email
	 * field's autofill. It is asked for once per page load — the relay's budget
	 * is sized for that, not for one per focus or click.
	 */
	let offer: AbortController | undefined;

	/**
	 * How long to wait for the field's offer to stand down before the button
	 * asks for its own. The browser settles a cancelled request promptly, but a
	 * password manager answering the ceremony may never acknowledge the abort at
	 * all — so the wait is bounded rather than a hang.
	 */
	const RELEASE_WAIT_MS = 250;

	/** A refused passkey call never reaches here, but the type checker insists. */
	const noRefusal = () => {};

	const sf = jsonForm(signInSchema, { email: carried.email ?? '', password: '' }, async (data) => {
		// A password sign-in is about to take the page: stand the field's offer
		// down so it cannot answer alongside it.
		offer?.abort();
		const res = await api('POST', '/api/account/login', { ...data, altcha: proof }, climb);
		altcha?.reset();
		if (!res.ok) {
			return res.error ?? 'That email and password did not match.';
		}
		flow.clear();
		// A session exists now: reopen the stream (it closed on the anonymous
		// answer) and wait for it to say so. The password is only the first
		// factor, so the next page is the code step; that page, not this one,
		// decides on the pairing detour.
		session.restart();
		await session.reached('basic');
		await goto(resolve('/(auth)/verify-code'));
	});

	const { form, errors, message, submitting, enhance } = sf;

	/**
	 * One passkey sign-in, end to end: ask the relay for a challenge, let the
	 * browser assert against it, and hand the answer back. `mediation` decides
	 * where the browser offers the passkey — `conditional` in the email field's
	 * autofill, `optional` in the modal picker.
	 */
	async function passkeySignIn(
		mediation: 'conditional' | 'optional',
		signal?: AbortSignal
	): Promise<void> {
		const begun = await api<PasskeyOptions>(
			'POST',
			'/api/account/passkey/begin',
			{ email: '' },
			noRefusal
		);
		if (!begun.ok || !begun.data) {
			announce(begun.error, mediation);
			return;
		}
		let credential: unknown;
		try {
			credential = await getAssertion(begun.data.options, { mediation, signal });
		} catch (error) {
			// A prompt the person dismissed is not an error to report; the
			// default message the button shows is only for anything else.
			if (failureOf(error) !== 'cancelled') {
				announce(null, mediation);
			}
			return;
		}
		const done = await api(
			'POST',
			'/api/account/passkey/finish',
			{ handle: begun.data.handle, credential },
			noRefusal
		);
		if (!done.ok) {
			announce(done.error, mediation);
			return;
		}
		flow.clear();
		// The assertion is both factors at once, so the stream reports `certain`
		// — not the `basic` a password leaves behind — and the console is already
		// signed in.
		session.restart();
		await session.reached('certain');
		await goto(resolve('/app'));
	}

	/** The field's offer never speaks; only the button, which a person pressed. */
	function announce(error: string | null, mediation: 'conditional' | 'optional'): void {
		if (mediation === 'optional') {
			message.set(error ?? 'That passkey was not accepted. Try again.');
		}
	}

	/**
	 * The button: a modal picker over whatever the browser holds. It is the
	 * guaranteed way in, so it first stands the field's offer down — only one
	 * credential request may be in flight, and the pending autofill ceremony
	 * would otherwise starve this one.
	 */
	async function signInWithPasskey(): Promise<void> {
		if (passkeyBusy) {
			return;
		}
		passkeyBusy = true;
		try {
			await releaseField();
			await passkeySignIn('optional');
		} finally {
			passkeyBusy = false;
		}
	}

	async function releaseField(): Promise<void> {
		const running = offer;
		offer = undefined;
		if (!running) {
			return;
		}
		running.abort();
		await new Promise((done) => setTimeout(done, RELEASE_WAIT_MS));
	}

	// Ask for the field's offer once the page is up, and take it with the page.
	onMount(() => {
		if (!passkeys) {
			return;
		}
		const controller = new AbortController();
		offer = controller;
		void passkeySignIn('conditional', controller.signal);
		return () => controller.abort();
	});
</script>

<svelte:head>
	<title>Sign in · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="signin-title">
	<h1 id="signin-title">Sign in</h1>
	<p class="lede">Your tunnels, devices and account.</p>

	<form class="form" method="POST" use:enhance novalidate>
		<EmailField
			bind:value={$form.email}
			error={$errors.email?.[0]}
			disabled={$submitting}
			{passkeys}
		/>

		<div class="field">
			<label for="password">Password</label>
			<input
				id="password"
				name="password"
				type={showPassword ? 'text' : 'password'}
				autocomplete="current-password"
				placeholder="Your password"
				bind:value={$form.password}
				disabled={$submitting}
				aria-invalid={$errors.password ? 'true' : undefined}
			/>
			<button
				type="button"
				class="toggle"
				aria-pressed={showPassword}
				onclick={() => (showPassword = !showPassword)}
			>
				{showPassword ? 'Hide password' : 'Show password'}
			</button>
			{#if $errors.password}<p class="field__error" aria-live="polite">
					{$errors.password[0]}
				</p>{/if}
		</div>

		<p><a href={resolve('/(auth)/forgot-password')}>Forgot password?</a></p>

		<Altcha purpose="login" bind:this={altcha} bind:payload={proof} />

		{#if $message}
			<p class="notice-error" role="alert">{$message}</p>
		{/if}

		<Keycap type="submit" loading={$submitting} disabled={!proof || $submitting} wide>
			{$submitting ? 'Signing in…' : 'Sign in'}
		</Keycap>
	</form>

	{#if passkeys}
		<div class="passkey">
			<Keycap
				type="button"
				variant="key"
				loading={passkeyBusy}
				disabled={$submitting || passkeyBusy}
				wide
				onclick={signInWithPasskey}
			>
				<Icon name="fingerprint" size={14} /> Sign in with a passkey
			</Keycap>
			<p class="passkey__note">
				No password, no emailed code — Face ID, Touch ID, Windows Hello or a security key.
			</p>
		</div>
	{/if}

	<p class="switch"><a href={resolve('/(auth)/sign-up')}>Create an account</a></p>
</Page>

<style lang="scss">
	.passkey {
		display: flex;
		flex-direction: column;
		gap: 8px;
		margin-top: 24px;
	}

	.passkey__note {
		margin: 0;
		color: var(--tw-muted);
		font-size: 14px;
		text-align: center;
	}
</style>
