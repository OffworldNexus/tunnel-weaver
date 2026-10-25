/**
 * Ways up (WVR-167/165).
 *
 * A level is not a permission the console decides: the relay reports it on the
 * session stream and, for the account it is talking to, names the steps that
 * reach each higher level — because they depend on how that account
 * authenticates. The console's job is to *perform* a step, and there are two
 * answers:
 *
 * * the nominal flow's pages (signing in, the emailed code), which the `(auth)`
 *   guard owns — reached by leaving the page the action was on;
 * * the inline escalation popin (`stepUp`), for a session that is already
 *   signed in and only needs a level re-proven in place.
 *
 * `climb` is the one entry point, for both kinds of caller: an action that knows
 * which level it needs, and a refusal handler answering the level the relay
 * asked for. It is also a write's refusal handler as-is — `api` takes
 * `(required, options)` and so does this — but nothing is retried for you: a
 * caller that wants the action finished after climbing re-issues it itself.
 */
import { notify } from '#lib/account/notices';
import { goto } from '$app/navigation';
import { resolve } from '$app/paths';

import { atLeast, type AuthLevel, session, type Step, type UpgradePath } from './session.svelte';
import { stepUp } from './stepup.svelte';

/**
 * The route that performs `step`, or `null` when the console performs it in
 * place (the inline popin). The nominal flow is pages; a signed-in session is
 * only ever a popin away from a level its own authentication can reach.
 *
 * The route *id* rather than a URL, so both callers `resolve` it themselves and
 * nothing here has to know what a URL looks like.
 */
export function stepPage(step: Step): '/(auth)/sign-in' | '/(auth)/verify-code' | null {
	switch (step) {
		case 'login':
			return '/(auth)/sign-in';
		case 'verify_email_otp':
			return '/(auth)/verify-code';
		case 'confirm_password':
			return null;
	}
}

/**
 * Takes the session up to `required` and reports whether it got there.
 *
 * The way up comes from the caller when it has one (a refusal names it in
 * `x-weaver-upgrade-paths`); otherwise it is read from the session itself. A
 * step the console performs in place is performed. A step that is a page hands
 * the person to the nominal flow: the guard takes over, the action is **not**
 * resumed — the console has left the page it was on — and this returns `false`.
 */
export async function climb(
	required: AuthLevel,
	options: UpgradePath[] = session.pathsTo(required)
): Promise<boolean> {
	if (atLeast(session.level, required)) {
		return true;
	}
	for (const step of options[0] ?? []) {
		const page = stepPage(step.step);
		if (page) {
			if (step.step === 'login') {
				// The session is gone: forget it, so the guards stop reading a
				// stale one.
				session.stop();
				notify('error', 'Your session has expired. Please sign in again.');
			}
			await goto(resolve(page), { replace: true });
			return false;
		}
		if (!(await stepUp.ask(required))) {
			return false;
		}
	}
	if (!atLeast(session.level, required)) {
		notify('error', `This needs a ${required} sign-in, which this console cannot ask for yet.`);
		return false;
	}
	return true;
}
