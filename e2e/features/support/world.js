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
  /** The CDP session driving this scenario's virtual authenticator (WVR-163). */
  cdp;
  /** That authenticator's id, for the presence toggle below. */
  authenticatorId = '';

  /**
   * Whether the virtual authenticator answers a ceremony on its own (WVR-163).
   *
   * It is off between steps on purpose: the sign-in page starts a *conditional*
   * ceremony of its own on load, to put the passkey in the field's autofill, and
   * a present authenticator answers that the instant it is issued — which is
   * exactly what picking the passkey out of autofill is, and not something a
   * scenario should get for free. So a ceremony that must need a click turns
   * presence on once the click has started it, while the autofill path turns it
   * on *before* the page loads: headless Chrome changes the answer only for
   * requests issued while presence is on, and leaves an already-pending
   * conditional request pending.
   */
  async present(enabled) {
    await this.cdp.send('WebAuthn.setAutomaticPresenceSimulation', {
      authenticatorId: this.authenticatorId,
      enabled
    });
  }

  url(pathname) {
    return new URL(pathname, harness.baseUrl).toString();
  }

  async open(pathname) {
    await this.page.goto(this.url(pathname));
  }
}

setWorldConstructor(WeaverWorld);
