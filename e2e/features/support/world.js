/**
 * The Cucumber World for the account-relay suite.
 *
 * One instance per scenario. It holds the browser page (created per scenario by
 * the hooks) plus the harness origins and a few thin conveniences. Mailbox
 * access is delegated to the harness module so scenarios never touch HTTP
 * details directly.
 */

import { setWorldConstructor, World } from '@cucumber/cucumber';
import {
  clearMail as clearCapturedMail,
  harness,
  latestVerificationLink as readLatestVerificationLink,
  messages as readMessages
} from './harness.js';

export class WeaverWorld extends World {
  constructor(options) {
    super(options);
    this.baseUrl = harness.baseUrl ?? '';
    this.mailUrl = harness.mailUrl ?? '';
    /** @type {import('playwright').Page | undefined} */
    this.page = undefined;
    /** @type {import('playwright').BrowserContext | undefined} */
    this.context = undefined;
    /** Per-scenario identity, seeded by the Background step. */
    this.name = '';
    this.email = '';
    this.password = '';

    // Bind mailbox helpers so they can be pulled off `this` in steps.
    this.messages = readMessages;
    this.clearMail = clearCapturedMail;
    this.latestVerificationLink = readLatestVerificationLink;
  }

  /** An absolute URL for a route path (`/`, `/sign-up`, …). */
  url(pathname = '/') {
    return new URL(pathname, this.baseUrl).toString();
  }

  /** Navigates the scenario page to a route path. */
  async open(pathname = '/') {
    await this.page.goto(this.url(pathname));
  }
}

setWorldConstructor(WeaverWorld);
