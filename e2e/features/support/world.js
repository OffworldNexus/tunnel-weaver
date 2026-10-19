/** The per-scenario World: the browser page plus what the scenario has seeded. */

import { setWorldConstructor, World } from '@cucumber/cucumber';
import { harness } from './harness.js';

class WeaverWorld extends World {
  /** @type {import('playwright').Page} */
  page;
  /** @type {import('playwright').BrowserContext} */
  context;
  /** The identity the Background seeds. */
  name = '';
  email = '';
  /** The reset link taken from the mailbox. */
  resetLink = '';
  /** The pending pairing, and the approvals of earlier ones keyed by machine. */
  pairing = { handle: '', fingerprint: '' };
  paired = {};
  /** Every request URL the page issued, so a handle leak can be disproved. */
  requestUrls = [];

  url(pathname) {
    return new URL(pathname, harness.baseUrl).toString();
  }

  async open(pathname) {
    await this.page.goto(this.url(pathname));
  }
}

setWorldConstructor(WeaverWorld);
