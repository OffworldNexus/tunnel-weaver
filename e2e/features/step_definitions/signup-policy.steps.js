/**
 * Steps for the relay-wide sign-up policy (WVR-98).
 *
 * The suite has no CLI, wizard or database handle, so a scenario states the
 * whole policy at once through the harness's `PUT /signup-policy` — the store
 * call the setup wizard and the CLI both end at. Every policy below names both
 * the default decision and the allow list, because a replacement does not merge
 * with what the previous step wrote.
 */

import { Given, Then, When } from '@cucumber/cucumber';

import * as assert from '../support/assertions.js';
import { SIGNUP_REFUSAL, VERIFICATION_SUBJECT, attemptCreateAccount } from '../support/flow.js';
import { mailCount, setSignupPolicy } from '../support/harness.js';

Given('sign-ups are closed to everyone', async function () {
  await setSignupPolicy({ default: 'deny', allow: [] });
});

Given('sign-ups are open to everyone', async function () {
  await setSignupPolicy({ default: 'allow', allow: [] });
});

Given('sign-ups are open only to my address', async function () {
  await setSignupPolicy({ default: 'deny', allow: [this.email] });
});

Given('sign-ups are open only to the domain {string}', async function (domain) {
  await setSignupPolicy({ default: 'deny', allow: [domain] });
});

// The refusal this feature adds is the alert the sign-up page renders from the
// relay's fixed message. The form is submitted but the code step must not come.
When('I try to create an account for {string}', async function (name) {
  await attemptCreateAccount(this, name);
});

Then('I see the sign-up refusal', async function () {
  await assert.seeAlert(this.page, SIGNUP_REFUSAL);
  const pathname = new URL(this.page.url()).pathname;
  if (pathname !== '/sign-up') {
    throw new Error(`Expected to stay on /sign-up, but the page went to "${pathname}".`);
  }
});

Then('no verification email is sent', async function () {
  // The verification mail is sent off the response path: give an absent send
  // time to show up before concluding there is none.
  await new Promise((resolve) => setTimeout(resolve, 3_000));
  const count = await mailCount(VERIFICATION_SUBJECT);
  if (count !== 0) {
    throw new Error(`Expected no verification email, but the mailbox holds ${count}.`);
  }
});
