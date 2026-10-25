/**
 * The code step's one job beyond rendering: make sure a code is really in
 * flight for this session (WVR-167).
 *
 * The password step already sends one, so arriving here straight after signing
 * in changes nothing — the relay's re-send cooldown answers without sending a
 * second email. But a `basic` session can reach this page with no code at all:
 * a session that predates the second factor, one whose code outlived its
 * lifetime, or a direct link. Asking on arrival is what makes the page
 * self-sufficient instead of dead until the person thinks to press re-send.
 *
 * It runs as a load rather than a mount effect so the send is decided before the
 * page renders, and re-running it is harmless: the cooldown is the guard.
 */
import { api } from '#lib/account/api';
import { session } from '#lib/app/session.svelte';
import { climb } from '#lib/app/upgrade';

import type { PageLoad } from './$types';

export const load: PageLoad = async ({ parent }) => {
	await parent();
	if (session.level !== 'basic') {
		return { codeSent: false };
	}
	const res = await api<{ status: string }>('POST', '/api/account/login/resend', {}, climb);
	// `cooldown` means a code was just sent, so nothing went out now; anything
	// else is a real send (or a failure, which the page reports).
	return { codeSent: res.ok && res.data?.status === 'second_factor' };
};
