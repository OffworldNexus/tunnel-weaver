/**
 * Landing-page steps: opening the front door and following its calls to action.
 */

import { Given, When } from '@cucumber/cucumber';
import { followCallToAction, openLanding } from '../support/flow.js';

Given('I open the landing page', async function () {
  await openLanding(this);
});

When('I follow the {string} call to action', async function (name) {
  await followCallToAction(this, name);
});
