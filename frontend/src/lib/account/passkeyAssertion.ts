/**
 * The passkey assertion the account plane performs on the session it already
 * has (WVR-163, WVR-166).
 *
 * Two callers need exactly this: the step-up popin, lifting a signed-in session
 * back to `Certain` in place, and the "try another way" chooser, finishing a
 * sign-in with the passkey instead of a code. Both call the same pair of
 * endpoints and run the same gesture between them, so the ceremony lives here
 * once. What a *refusal* means is the caller's business — the popin closes and
 * answers no, the chooser climbs — so it is passed in, exactly as `api` takes it.
 */
import { api, type RefusalHandler } from '#lib/account/api';
import { failureOf, getAssertion, type PasskeyOptions, supported } from '#lib/account/webauthn';

/** The two halves of the assertion ceremony. */
const BEGIN_URL = '/api/account/passkey/step-up/begin';
const FINISH_URL = '/api/account/passkey/step-up/finish';

/** The relay's answer when the session turns out to have nothing to assert for. */
const CONFLICT = 409;

/** How one attempt at the ceremony ended. */
export interface AssertionResult {
	/** The relay took the assertion; the caller waits for the stream's level. */
	asserted: boolean;
	/** The person gave up (or this browser cannot do passkeys): nothing to report. */
	cancelled: boolean;
	/** The relay says there is nothing left to assert for — the session is settled. */
	settled: boolean;
	/** What to show on any other failure; empty when there is nothing to say. */
	message: string;
}

/**
 * Runs the ceremony once.
 *
 * Nothing is retried and the level is not waited for here: the caller knows what
 * level it was after and what to do if it never arrives.
 */
export async function assertOnThisSession(onRefusal: RefusalHandler): Promise<AssertionResult> {
	const nothing = { asserted: false, cancelled: false, settled: false, message: '' };
	const begun = await api<PasskeyOptions>('POST', BEGIN_URL, {}, onRefusal);
	if (begun.status === CONFLICT) {
		return { ...nothing, settled: true };
	}
	if (!begun.ok || !begun.data) {
		return { ...nothing, message: begun.error ?? 'We could not start that passkey. Try again.' };
	}
	let credential: unknown;
	try {
		credential = await getAssertion(begun.data.options, { mediation: 'optional' });
	} catch (error) {
		if (failureOf(error) === 'cancelled') {
			return { ...nothing, cancelled: true };
		}
		return {
			...nothing,
			message: supported()
				? 'That passkey was not accepted. Try again.'
				: 'This browser cannot use passkeys.'
		};
	}
	const done = await api('POST', FINISH_URL, { handle: begun.data.handle, credential }, onRefusal);
	if (!done.ok) {
		return { ...nothing, message: done.error ?? 'That passkey was not accepted. Try again.' };
	}
	return { ...nothing, asserted: true };
}
