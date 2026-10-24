/** WVR-168: keeping a signed-in person out of the account-entry pages. */

import { Given } from '@cucumber/cucumber';

/** Must match `#lib/account/state` — the pairing record kept in localStorage. */
const PAIRING_KEY = 'weaver.pairing';

/**
 * Marks the pending pairing as a sign-in detour: the state a person is left in
 * after opening a pairing link while signed out. The guard must then send a
 * signed-in visitor on to the confirmation rather than the console.
 */
Given('a sign-in detour is pending', async function () {
  await this.page.evaluate(
    ({ key, handle }) => localStorage.setItem(key, JSON.stringify({ handle, detour: true })),
    { key: PAIRING_KEY, handle: this.pairing.handle }
  );
});
