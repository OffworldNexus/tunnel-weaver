/**
 * The console's inline escalation: proving the password again, in a popin.
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
 * `ask` resolves when the session holds the level again, or `false` when the
 * person gave up. `climb` in `upgrade.ts` is the friendlier face of it: it reads
 * the way up the relay named and decides between this popin and the nominal
 * flow's pages. Actions should reach for `climb`, not for this, unless they are
 * driving a flow of their own.
 */
import { api } from '#lib/account/api';

import { type AuthLevel, session } from './session.svelte';

/** The `confirm_password` step's endpoint. */
const CONFIRM_PASSWORD_URL = '/api/account/confirm-password';

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
		if (!res.ok) {
			this.busy = false;
			if (!res.refused) {
				this.error = res.error ?? 'That is not your password.';
			}
			return;
		}
		// The relay recorded the proof; wait for the session stream to report the
		// new level, so whatever was refused is not refused again for a frame.
		await session.reached(this.#required);
		this.busy = false;
		this.open = false;
		this.#settle(true);
	}

	/** The person gave up: Cancel, Escape, or the close button. */
	cancel(): void {
		this.open = false;
		this.error = '';
		this.#settle(false);
	}

	#settle(reached: boolean): void {
		const answer = this.#answer;
		this.#answer = undefined;
		answer?.(reached);
	}
}

/** The one inline escalation popin, shared by every action that needs one. */
export const stepUp = new StepUp();
