/**
 * The console's inline escalation: proving who you are again, in a popin.
 *
 * Authentication itself is pages — signing up, signing in, the emailed code, a
 * verification link — and the `(auth)` guard owns those. What this is for is the
 * *upgrade* of a session that is already signed in: a sensitive action needs a
 * level the session has aged out of, and re-proving it must not cost the person
 * the page they were on.
 *
 * So there is one popin, mounted once over the whole app, askable from anywhere:
 *
 * ```ts
 * if (await stepUp.ask('certain')) { … }
 * ```
 *
 * It offers whatever the session's own ways up hold: the password, and — once
 * the account has a passkey — an assertion, which is faster and proves more
 * (WVR-163). `ask` resolves when the session holds the level again, or `false`
 * when the person gave up. `climb` in `upgrade.ts` is the friendlier face of it:
 * it reads the way up the relay named and decides between this popin and the
 * nominal flow's pages. Actions should reach for `climb`, not for this, unless
 * they are driving a flow of their own.
 */
import { api } from '#lib/account/api';
import { failureOf, getAssertion, type PasskeyOptions, supported } from '#lib/account/webauthn';

import { atLeast, type AuthLevel, session } from './session.svelte';

/** The `confirm_password` step's endpoint. */
const CONFIRM_PASSWORD_URL = '/api/account/confirm-password';

/** The `assert_passkey` step's two halves. */
const STEP_UP_BEGIN_URL = '/api/account/passkey/step-up/begin';
const STEP_UP_FINISH_URL = '/api/account/passkey/step-up/finish';

/** The relay's answer when the session turns out to have nothing to confirm. */
const CONFLICT = 409;

class StepUp {
	/** Whether the popin is showing. The root layout binds it. */
	open = $state(false);
	/** The refusal to show on the field; empty for none. */
	error = $state('');
	/** Whether a check is in flight. */
	busy = $state(false);

	/** How the person answered, once they have. */
	#answer: ((reached: boolean) => void) | undefined;
	/** The level the open popin is asking for, to know what to wait for. */
	#required: AuthLevel = 'certain';

	/**
	 * Whether the open popin can offer an assertion instead of a password: the
	 * relay names `assert_passkey` among the ways up exactly when the account
	 * holds a passkey, so this is the relay's answer, not a guess.
	 */
	get passkeyAvailable(): boolean {
		return session
			.pathsTo(this.#required)
			.some((path) => path.some((step) => step.step === 'assert_passkey'));
	}

	/**
	 * Shows the popin and resolves once the session holds `required` again — or
	 * `false` if the person closed it instead.
	 *
	 * There is one popin, so a second ask while one is open is not meaningful:
	 * it takes the popin over and the first ask resolves `false`, as it did not
	 * get what it asked for.
	 */
	ask(required: AuthLevel): Promise<boolean> {
		this.#settle(false);
		this.#required = required;
		this.error = '';
		this.open = true;
		return new Promise((resolve) => {
			this.#answer = resolve;
		});
	}

	/** The password was typed: ask the relay to prove it again. */
	async submit(password: string): Promise<void> {
		if (this.busy) {
			return;
		}
		this.error = '';
		this.busy = true;
		const res = await api('POST', CONFIRM_PASSWORD_URL, { password }, () => {
			// Refused for a level this popin cannot reach — it stands on `strong` —
			// so there is nothing to climb from in here: close, and let whoever asked
			// decide again from the level the relay named.
			this.open = false;
			this.#settle(false);
		});
		if (res.status === CONFLICT) {
			// The relay says this sign-in is already confirmed, so there was nothing
			// to ask for: a console that was behind on its level. Whatever asked can
			// carry on from what it holds.
			this.busy = false;
			this.open = false;
			this.#settle(atLeast(session.level, this.#required));
			return;
		}
		if (!res.ok) {
			this.busy = false;
			if (!res.refused) {
				this.error = res.error ?? 'That is not your password.';
			}
			return;
		}
		await this.#reached();
	}

	/**
	 * The passkey was asserted: same ceremony as signing in, in place, on the
	 * session that is already open.
	 *
	 * It is one gesture with no password to type, which is exactly why the popin
	 * offers it beside the form.
	 */
	async submitPasskey(): Promise<void> {
		if (this.busy) {
			return;
		}
		this.error = '';
		this.busy = true;
		const begun = await api<PasskeyOptions>('POST', STEP_UP_BEGIN_URL, {}, () => {
			// Same refusal as the password's: nothing in this popin can climb.
			this.open = false;
			this.#settle(false);
		});
		if (begun.status === CONFLICT) {
			this.busy = false;
			this.open = false;
			this.#settle(atLeast(session.level, this.#required));
			return;
		}
		if (!begun.ok || !begun.data) {
			this.busy = false;
			this.error = begun.error ?? 'We could not start that passkey. Try again.';
			return;
		}
		let credential: unknown;
		try {
			credential = await getAssertion(begun.data.options, { mediation: 'optional' });
		} catch (error) {
			this.busy = false;
			if (failureOf(error) === 'cancelled') {
				return;
			}
			this.error = supported()
				? 'That passkey was not accepted. Try again.'
				: 'This browser cannot use passkeys.';
			return;
		}
		const done = await api(
			'POST',
			STEP_UP_FINISH_URL,
			{ handle: begun.data.handle, credential },
			() => {
				this.open = false;
				this.#settle(false);
			}
		);
		if (!done.ok) {
			this.busy = false;
			if (!done.refused) {
				this.error = done.error ?? 'That passkey was not accepted. Try again.';
			}
			return;
		}
		await this.#reached();
	}

	/** The person gave up: Cancel, Escape, or the close button. */
	cancel(): void {
		this.open = false;
		this.error = '';
		this.#settle(false);
	}

	/** The relay recorded the proof; wait for the stream to report the level. */
	async #reached(): Promise<void> {
		await session.reached(this.#required);
		this.busy = false;
		this.open = false;
		this.#settle(true);
	}

	#settle(reached: boolean): void {
		const answer = this.#answer;
		this.#answer = undefined;
		answer?.(reached);
	}
}

/** The one inline escalation popin, shared by every action that needs one. */
export const stepUp = new StepUp();
