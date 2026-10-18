/**
 * Pairing steps: the browser half of enrolling a machine.
 *
 * The terminal half — `weave pair`, `weave start`, Ctrl-C, the key floor — is
 * CLI-only and lives in the Rust tests. Here the harness seeds the pending
 * pairing the CLI would have created, the scenario opens the link it would have
 * printed, and the message the terminal would have received is read back from
 * the harness's stand-in channel.
 */

import { Given, Then, When } from '@cucumber/cucumber';
import * as assert from '../support/assertions.js';
import { followLink } from '../support/flow.js';

/** Opens the pair page at the URL the product prints for a handle. */
async function openPairLink(world, handle) {
  await world.page.goto(await world.pairingUrl(handle));
}

/**
 * A fresh visit to the same link. Playwright's `goto` to the same path with only
 * a different fragment is a same-document hash change, so the SPA would keep the
 * screen it is already showing; a link's verdict is judged on a real load, which
 * is also what a person pasting the link into a new tab gets.
 */
async function reloadPairLink(world, handle) {
  await openPairLink(world, handle);
  await world.page.reload();
}

/** Records every request the page issues, so a handle leak can be disproved. */
function traceRequests(world) {
  world.page.on('request', (request) => world.requestUrls.push(request.url()));
}

async function seed(world, target) {
  // The trace goes up before the pair page loads: any request made from here on
  // is covered, and the handle does not exist in the browser before that.
  traceRequests(world);
  const seeded = await world.seedPairing(target);
  world.pairingHandle = seeded.handle;
  world.pairingFingerprint = seeded.fingerprint;
}

Given('a pending pairing is seeded for the machine {string}', async function (machine) {
  await seed(this, { machine });
});

Given('the machine {string} is paired', async function (machine) {
  await seed(this, { machine });
  await openPairLink(this, this.pairingHandle);
  await this.page
    .getByRole('button', { name: 'Approve this machine', exact: true })
    .click({ force: true });
  await assert.seeHeading(this.page, 'Machine approved');
  const outcome = await this.pairingOutcome(this.pairingHandle);
  if (outcome.type !== 'approved') {
    throw new Error(`Expected the pairing to be approved, but got ${JSON.stringify(outcome)}.`);
  }
  this.pairedMachines[machine] = outcome;
  // Leave the pair page the way a person does, so the next link is a real load.
  await followLink(this, 'Go to your account');
  await assert.seeText(this.page, this.email);
});

Given('{string} lost its key and asks to pair again', async function (machine) {
  const paired = this.pairedMachines[machine];
  if (!paired) throw new Error(`No machine "${machine}" was paired in this scenario.`);
  await seed(this, { machineId: paired.machine_id });
});

When('I open the pairing link from the fragment', async function () {
  await openPairLink(this, this.pairingHandle);
});

When('I open the same pairing link again', async function () {
  await reloadPairLink(this, this.pairingHandle);
});

When('I open a pairing link for an unknown handle', async function () {
  // Well-formed (64 hex characters) but never seeded, like a link whose request
  // has already been spent or whose terminal has gone away.
  this.pairingHandle = 'f'.repeat(64);
  await openPairLink(this, this.pairingHandle);
});

Then('the confirmation proposes the machine {string} and a person slug', async function (machine) {
  await assert.seeLabel(this.page, 'Machine name');
  await assert.seeFieldValue(
    this.page,
    this.page.getByLabel('Machine name', { exact: true }),
    machine,
    'the proposed machine name'
  );
  await assert.seeLabel(this.page, 'Person slug');
  // The slug is uniquified against every person the relay already knows, so the
  // exact value depends on the scenarios that ran before this one: assert the
  // shape the label rules demand, not a literal.
  const slug = await this.page.getByLabel('Person slug', { exact: true }).inputValue();
  if (!/^[a-z0-9]{1,15}$/.test(slug)) {
    throw new Error(
      `Expected the proposed person slug to match ^[a-z0-9]{1,15}$, but it was "${slug}".`
    );
  }
});

Then('the confirmation proposes the machine {string} under the existing person', async function (machine) {
  await assert.seeFieldValue(
    this.page,
    this.page.getByLabel('Machine name', { exact: true }),
    machine,
    'the proposed machine name'
  );
  // The account already has its person: the slug is fixed, so not offered.
  if ((await this.page.getByLabel('Person slug', { exact: true }).count()) !== 0) {
    throw new Error('The person slug is offered for editing although the account already has one.');
  }
});

Then('the confirmation names {string} with nothing to edit', async function (machine) {
  const paired = this.pairedMachines[machine];
  await assert.seeText(this.page, `${paired.person}/${machine}`);
  for (const label of ['Machine name', 'Person slug']) {
    if ((await this.page.getByLabel(label, { exact: true }).count()) !== 0) {
      throw new Error(`"${label}" is editable, but an existing machine's names are fixed.`);
    }
  }
});

Then('the pairing key fingerprint is shown', async function () {
  await assert.seeText(this.page, 'Key fingerprint');
  // The seed reports the fingerprint it fabricated, so the exact value is
  // asserted without coupling the feature to a constant.
  await assert.seeText(this.page, this.pairingFingerprint, { exact: true });
});

Then('the address bar carries no pairing handle', async function () {
  // The page strips the fragment on mount, so wait for the capability to be gone
  // from the address bar (and with it the history entry and any `Referer`).
  const deadline = Date.now() + 20_000;
  for (;;) {
    const url = new URL(this.page.url());
    if (url.search === '' && url.hash === '') break;
    if (Date.now() >= deadline) {
      throw new Error(
        `Expected the address bar to hold a bare path with no query or fragment, but it was ` +
          `"${this.page.url()}".`
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  const href = this.page.url();
  if (href.includes(this.pairingHandle)) {
    throw new Error(`The address bar still carries the pairing handle: "${href}".`);
  }
});

Then('no request carried the pairing handle', async function () {
  if (this.requestUrls.length === 0) {
    throw new Error('No requests were recorded, so the leak check would pass vacuously.');
  }
  const leaky = this.requestUrls.filter((url) => url.includes(this.pairingHandle));
  if (leaky.length > 0) {
    throw new Error(
      `The pairing handle appeared in ${leaky.length} request URL(s):\n  ${leaky.join('\n  ')}`
    );
  }
});

When('I approve the machine', async function () {
  // The keycap's layered art defeats Playwright's stability check, so the click
  // is forced (same caveat as the other keycap controls).
  await this.page
    .getByRole('button', { name: 'Approve this machine', exact: true })
    .click({ force: true });
});

When('I move the machine to the new key', async function () {
  await this.page
    .getByRole('button', { name: 'Use the new key', exact: true })
    .click({ force: true });
});

When('I reject the machine', async function () {
  await this.page.getByRole('button', { name: 'Reject', exact: true }).click({ force: true });
});

When('I follow the {string} link', async function (name) {
  await followLink(this, name);
});

Then('I see the instruction to re-run {string}', async function (command) {
  await assert.seeText(this.page, `Re-run ${command} to try again.`);
});

Then('the terminal is told it is paired as the machine {string}', async function (machine) {
  const outcome = await this.pairingOutcome(this.pairingHandle);
  if (outcome.type !== 'approved' || outcome.machine !== machine) {
    throw new Error(
      `Expected the terminal to be approved as "${machine}", but it got ${JSON.stringify(outcome)}.`
    );
  }
  if (!Number.isInteger(outcome.machine_id) || !/^[a-z0-9]{1,15}$/.test(outcome.person)) {
    throw new Error(`The approval lacks a machine id or a person slug: ${JSON.stringify(outcome)}.`);
  }
});

Then('the terminal is told it is still the machine {string}', async function (machine) {
  const outcome = await this.pairingOutcome(this.pairingHandle);
  const before = this.pairedMachines[machine];
  if (outcome.type !== 'approved' || outcome.machine_id !== before.machine_id) {
    throw new Error(
      `Expected machine ${before.machine_id} ("${machine}") to keep its id, but the terminal got ` +
        `${JSON.stringify(outcome)}.`
    );
  }
});

Then('the terminal is told the pairing failed with {string}', async function (code) {
  const outcome = await this.pairingOutcome(this.pairingHandle);
  if (outcome.type !== 'failed' || outcome.code !== code) {
    throw new Error(
      `Expected the terminal to get a "${code}" failure, but it got ${JSON.stringify(outcome)}.`
    );
  }
});
