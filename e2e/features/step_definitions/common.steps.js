/**
 * Shared, view-level steps used by more than one feature.
 *
 * These only assert what a person can see; feature-specific journeys live in
 * `landing.steps.js` and `account.steps.js`. Steps are registered globally by
 * Cucumber, so keeping the generic assertions here avoids duplication.
 */

import { Then } from '@cucumber/cucumber';
import * as assert from '../support/assertions.js';

Then('I see the {string} heading', async function (name) {
  await assert.seeHeading(this.page, name);
});

Then('I see the welcome heading {string}', async function (name) {
  await assert.seeHeading(this.page, name);
});

Then('I see a link to {string}', async function (name) {
  await assert.seeLink(this.page, name);
});

Then('I see the sign-in error {string}', async function (text) {
  await assert.seeAlert(this.page, text);
});

Then('the verified email is shown as the account address', async function () {
  await assert.seeFieldValue(
    this.page,
    this.page.getByLabel('Email'),
    this.email,
    'the verified email field'
  );
});

Then('I see the signed-in identity for {string}', async function (name) {
  await assert.seeHeading(this.page, 'Your account');
  await assert.seeDefinition(this.page, name);
  await assert.seeDefinition(this.page, this.email);
});
