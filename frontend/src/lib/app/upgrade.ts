/**
 * Taking a person up to the level an action needs (WVR-167).
 *
 * The console knows which level each of its actions requires; the relay says
 * how this account gets there — on the session stream ahead of time, and on a
 * refusal after the fact. Either way that is a list of options, each an ordered
 * list of steps, and each step says where it will leave the session. This is
 * where a step becomes a page, and where a climb that cannot finish what it
 * started says so rather than dropping the person back into a refusal.
 */
import type { RefusalHandler } from '#lib/account/api';
import { notify } from '#lib/account/notices';
import { goto } from '$app/navigation';
import { resolve } from '$app/paths';

import { atLeast, type AuthLevel, session, type Step, type UpgradePath } from './session.svelte';

/** The page that performs `step`, or empty when no page does yet. */
export function stepRoute(step: Step): string {
	switch (step) {
		case 'login':
			return resolve('/(auth)/sign-in');
		case 'verify_email_otp':
			return resolve('/(auth)/verify-code');
		// Re-typing the password has no page until a sensitive action needs
		// `certain` (WVR-165).
		case 'confirm_password':
			return '';
	}
}

/**
 * Sends the person to the first step of the preferred way to reach `required`,
 * asking the relay for that way when the caller has none to hand. Returns
 * whether the console could take them all the way.
 */
export async function climb(
	required: AuthLevel,
	options: UpgradePath[] = session.pathsTo(required)
): Promise<boolean> {
	const path = options[0] ?? [];
	// Only the steps this console can actually perform; a path may end in one
	// it has no page for (re-typing the password, WVR-165).
	const performable = path.filter((set) => stepRoute(set.step) !== '');
	const first = performable[0];
	if (!first) {
		notify('error', `This needs a ${required} sign-in, which this console cannot ask for yet.`);
		return false;
	}
	// Say so when the climb cannot reach the level the action wanted, or the
	// person is walked up only to be refused again.
	const reaches = performable.at(-1)?.reaches ?? 'none';
	if (!atLeast(reaches, required)) {
		notify(
			'error',
			`This needs a ${required} sign-in; this console can take you to ${reaches} for now.`
		);
	}
	switch (first.step) {
		case 'login':
			// The session is gone: forget it, so the guards stop reading a stale
			// one.
			session.stop();
			notify('error', 'Your session has expired. Please sign in again.');
			await goto(resolve('/(auth)/sign-in'), { replace: true });
			return true;
		case 'verify_email_otp':
			await goto(resolve('/(auth)/verify-code'), { replace: true });
			return true;
		// Filtered out by `performable`; kept for exhaustiveness.
		case 'confirm_password':
			return false;
	}
}

/**
 * The refusal handler for an action whose only answer to "not enough" is to
 * take the person up: the action is not retried — they start it again once
 * they are back.
 */
export const stepUp: RefusalHandler = async (required, options) => {
	await climb(required, options);
};
