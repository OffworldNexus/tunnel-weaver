/**
 * The one place a route loader turns a failed account-API result into a throw.
 *
 * A loader never returns a partly filled object: the page either has complete
 * data or an error, so no component ever has to tell "absent" from "zero". A
 * dead session (401) is not a page error; it sends the person back to sign in.
 *
 * These loaders run in the browser only — the root `+layout.ts` turns SSR off,
 * because the account API is same-origin behind a session cookie a server
 * render could not send.
 */
import { error, redirect } from '@sveltejs/kit';

import type { ApiResult } from '#lib/account/api';

export function unwrap<T>(res: ApiResult<T>, fallback: string): T {
	if (res.ok && res.data) {
		return res.data;
	}
	if (res.status === 401) {
		redirect(307, '/sign-in');
	}
	error(res.status >= 400 && res.status <= 599 ? res.status : 502, res.error ?? fallback);
}
