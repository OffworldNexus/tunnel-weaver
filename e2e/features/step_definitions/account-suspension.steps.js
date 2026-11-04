/**
 * Steps for account suspension (WVR-178).
 *
 * The operator's ban reaches the relay through the harness's `PUT /account-state`
 * (see `support/harness.js`): the CLI is a control-socket client and the suite
 * has no socket, so the harness calls the same `Suspension` handle the daemon's
 * control server does — the store transaction, the session push and the tunnel
 * eviction all run for real.
 *
 * The refusal sentence is the relay's one fixed line, spelled here the way
 * `weaver_server::account::suspension::SUSPENDED` spells it (the suite is JS and
 * cannot import it). The operator's reason is never part of it, which is what
 * the "never shown" step below holds every banning scenario to.
 */

import { Given, Then, When } from '@cucumber/cucumber';

import * as assert from '../support/assertions.js';
import { setAccountState } from '../support/harness.js';

/** The one thing a suspended person is told, whoever they are (WVR-178). */
export const SUSPENDED = 'This account has been suspended. Contact the relay operator.';

/** How long a pushed sign-out may take before it is no longer "on the spot". */
const SIGN_OUT_BUDGET_MS = 10_000;

Given('the operator bans my account with the reason {string}', async function (reason) {
  // Kept on the World so the "never shown" assertion below has the exact text to
  // look for; a distinctive reason is what makes a leak detectable at all.
  this.banReason = reason;
  await setAccountState({ email: this.email, state: 'banned', reason });
});

When('the operator lifts the ban on my account', async function () {
  // The harness ignores `reason` for an unban, but the field is mandatory.
  await setAccountState({ email: this.email, state: 'active', reason: '' });
});

// WVR-178: nothing here clicks or reloads. The console is left on the overview
// and leaves because the session stream told it the session is gone — a tab that
// only noticed on its next request would sit still for the whole budget.
Then('the console signs me out on its own', async function () {
  await this.page.waitForURL(/\/sign-in$/, { timeout: SIGN_OUT_BUDGET_MS });
  await assert.seeHeading(this.page, 'Sign in');
});

Then('I see the suspension refusal', async function () {
  await assert.seeAlert(this.page, SUSPENDED);
  const pathname = new URL(this.page.url()).pathname;
  if (pathname !== '/sign-in') {
    throw new Error(`Expected the suspension refusal on /sign-in, but the page went to "${pathname}".`);
  }
});

Then('I do not see the suspension refusal', async function () {
  // Only meaningful right after the page has answered something: the caller
  // asserts that answer first, so this proves the sentence was *replaced*, not
  // merely late.
  const count = await this.page.getByRole('alert').filter({ hasText: SUSPENDED }).count();
  if (count !== 0) {
    throw new Error(`Expected no suspension refusal at ${this.page.url()}, but found ${count}.`);
  }
});

// WVR-178: the operator's note stays in the store. The page's text is where a
// person would read it, and the URLs the tab issued are where it would travel if
// it were ever smuggled through a redirect (the SSO refusal path is one).
Then('the reason the operator recorded is never shown', async function () {
  const reason = this.banReason;
  if (!reason) throw new Error('No ban reason was recorded: the ban step must run first.');
  const shown = await this.page.evaluate(() => document.body.innerText);
  if (shown.includes(reason)) {
    throw new Error(`The ban reason "${reason}" was rendered at ${this.page.url()}.`);
  }
  const leaked = this.requestUrls.find((url) => url.includes(reason));
  if (leaked) {
    throw new Error(`The ban reason "${reason}" leaked into a request URL: ${leaked}`);
  }
});
