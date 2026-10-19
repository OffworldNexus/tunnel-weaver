/**
 * Pairing steps: the browser half of enrolling a machine. The harness seeds the
 * pending pairing `weave pair` would have opened, the scenario opens the link it
 * would have printed, and the harness reports what the terminal was told.
 */

import { Given, Then, When } from '@cucumber/cucumber';
import * as assert from '../support/assertions.js';
import { press } from '../support/flow.js';
import { pairingOutcome, pairingUrl, seedPairing } from '../support/harness.js';

const SLUG = /^[a-z0-9]{1,15}$/;

async function openPairingLink(world) {
  await world.page.goto(await pairingUrl(world.pairing.handle));
}

async function expectApproved(world) {
  const outcome = await pairingOutcome(world.pairing.handle);
  if (outcome.type !== 'approved' || !Number.isInteger(outcome.machine_id) || !SLUG.test(outcome.person)) {
    throw new Error(`Expected the terminal to be approved, but it got ${JSON.stringify(outcome)}.`);
  }
  return outcome;
}

Given('a pending pairing is seeded for the machine {string}', async function (machine) {
  this.pairing = await seedPairing({ machine });
});

Given('the machine {string} is paired', async function (machine) {
  this.pairing = await seedPairing({ machine });
  await openPairingLink(this);
  await press(this, 'Approve this machine');
  await assert.seeHeading(this.page, 'Machine approved');
  this.paired[machine] = await expectApproved(this);
  // Leave the pair page, so the next link is a real load.
  await this.page.getByRole('link', { name: 'Go to your account', exact: true }).click();
  await assert.seeHeading(this.page, 'Your account');
});

Given('{string} lost its key and asks to pair again', async function (machine) {
  this.pairing = await seedPairing({ machine_id: this.paired[machine].machine_id });
});

When('I open the pairing link', async function () {
  await openPairingLink(this);
});

When('I open the same pairing link again', async function () {
  // Going to the same path with only a new fragment is a same-document
  // navigation; a person pasting the link into a new tab gets a real load.
  await openPairingLink(this);
  await this.page.reload();
});

When('I open a pairing link for an unknown handle', async function () {
  // Well-formed, but never seeded: like a request whose terminal has gone.
  this.pairing = { handle: 'f'.repeat(64), fingerprint: '' };
  await openPairingLink(this);
});

Then('the confirmation proposes the machine {string} and a person slug', async function (machine) {
  await assert.seeFieldValue(this.page, 'Machine name', machine);
  // The slug is made unique against every person the relay knows, so its value
  // depends on earlier scenarios: assert its shape.
  const slug = await this.page.getByLabel('Person slug', { exact: true }).inputValue();
  if (!SLUG.test(slug)) throw new Error(`The proposed person slug "${slug}" is not a valid label.`);
});

Then('the confirmation proposes the machine {string} under the existing person', async function (machine) {
  await assert.seeFieldValue(this.page, 'Machine name', machine);
  await assert.seeNoField(this.page, 'Person slug');
});

Then('the confirmation names {string} with nothing to edit', async function (machine) {
  await assert.seeText(this.page, `${this.paired[machine].person}/${machine}`);
  await assert.seeNoField(this.page, 'Machine name');
  await assert.seeNoField(this.page, 'Person slug');
});

Then('the pairing key fingerprint is shown', async function () {
  await assert.seeText(this.page, this.pairing.fingerprint, { exact: true });
});

Then('the address bar carries no pairing handle', async function () {
  // The page strips the fragment on mount.
  await this.page.waitForURL((url) => url.search === '' && url.hash === '');
});

Then('no request carried the pairing handle', function () {
  const leaky = this.requestUrls.filter((url) => url.includes(this.pairing.handle));
  if (leaky.length > 0) {
    throw new Error(`The pairing handle appeared in request URLs:\n  ${leaky.join('\n  ')}`);
  }
});

When('I set the person slug to {string}', async function (slug) {
  await this.page.getByLabel('Person slug', { exact: true }).fill(slug);
});

When('I set the person slug to a fresh one', async function () {
  const slug = `p${Date.now().toString(36)}${Math.random().toString(36).slice(2, 5)}`;
  await this.page.getByLabel('Person slug', { exact: true }).fill(slug);
});

When('I approve the machine', async function () {
  await press(this, 'Approve this machine');
});

When('I move the machine to the new key', async function () {
  await press(this, 'Use the new key');
});

When('I reject the machine', async function () {
  await press(this, 'Reject');
});

Then('the terminal is told it is paired as the machine {string}', async function (machine) {
  const outcome = await expectApproved(this);
  if (outcome.machine !== machine) {
    throw new Error(`Expected the terminal to be paired as "${machine}", but got "${outcome.machine}".`);
  }
});

Then('the terminal is told it is still the machine {string}', async function (machine) {
  const outcome = await expectApproved(this);
  if (outcome.machine_id !== this.paired[machine].machine_id) {
    throw new Error(`Expected "${machine}" to keep id ${this.paired[machine].machine_id}, got ${outcome.machine_id}.`);
  }
});

Then('the terminal is told the pairing failed with {string}', async function (code) {
  const outcome = await pairingOutcome(this.pairing.handle);
  if (outcome.type !== 'failed' || outcome.code !== code) {
    throw new Error(`Expected a "${code}" failure, but the terminal got ${JSON.stringify(outcome)}.`);
  }
});
