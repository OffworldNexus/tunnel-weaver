/**
 * Steps for signing in through an external identity provider (WVR-175).
 *
 * The suite never reaches a real provider: the e2e harness registers a fake
 * provider whose authorization redirect points straight back at the relay with
 * a code that is the assertion scripted here. Everything else — the pending
 * flow, the callback, account creation, linking, the emailed code and the
 * session level — is the relay's real pipeline.
 */

import { Given, When } from '@cucumber/cucumber';

import { press, VERIFICATION_SUBJECT } from '../support/flow.js';
import { expectSso, latestMailCode } from '../support/harness.js';

/** The durable subject the fake provider reports for this scenario's address. */
function subjectFor(email) {
  return `e2e-${email}`;
}

Given('the fake provider vouches for the address', async function () {
  this.ssoSubject = subjectFor(this.email);
  await expectSso({
    subject: this.ssoSubject,
    email: this.email,
    email_verified: true,
    name: this.name
  });
});

Given('the fake provider does not vouch for the address', async function () {
  this.ssoSubject = subjectFor(this.email);
  await expectSso({
    subject: this.ssoSubject,
    email: this.email,
    email_verified: false,
    name: this.name
  });
});

Given('a stranger claims my address through the fake provider', async function () {
  await expectSso({
    subject: `attacker-${Date.now().toString(36)}`,
    email: this.email,
    email_verified: false,
    name: 'A Stranger'
  });
});

When('I sign in with the fake provider', async function () {
  // The button is the sign-in grid's entry for the enabled provider, labelled
  // from `/api/account/config`; clicking it is a whole-page navigation.
  await this.page.getByRole('button', { name: 'Fake provider' }).click();
});

When('I enter the address-verification code', async function () {
  // An SSO sign-up whose address the provider did not vouch for is settled on
  // the ordinary code step; unlike the signup flow it then lands on the console
  // rather than on set-password.
  await this.page
    .getByLabel('Code', { exact: true })
    .fill(await latestMailCode(VERIFICATION_SUBJECT));
  await press(this, 'Continue');
});
