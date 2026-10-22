/**
 * Machine-console steps: the live half. A change is made outside the page under
 * test — in a second tab, or straight from the page's own session — and the
 * suite asserts the change arrived without a reload.
 */

import { Then, When } from '@cucumber/cucumber';
import * as assert from '../support/assertions.js';

/**
 * The machines list has two headings named "Machines" — the page head and the
 * panel — so the page check must pin the level rather than the name alone.
 */
function seeMachinesPage(page) {
  return page
    .getByRole('heading', { level: 1, name: 'Machines', exact: true })
    .waitFor({ state: 'visible' });
}

When('I open the machines page', async function () {
  await this.open('/app/machines');
  await seeMachinesPage(this.page);
  // A value that can only survive if the page never reloads: a navigation would
  // wipe the window. The live update must leave it in place.
  await this.page.evaluate(() => {
    window.__liveProbe = 'kept';
  });
});

Then('I see the machine {string} in the list', async function (name) {
  await assert.seeText(this.page, name, { exact: true });
});

When('in another tab I rename {string} to {string}', async function (from, to) {
  const tab = await this.context.newPage();
  tab.setDefaultTimeout(20_000);
  await tab.goto(this.url('/app/machines'));
  await seeMachinesPage(tab);

  // The data rows carry `role="link"` (the whole row navigates), so the action
  // buttons are found by their own name rather than through the row.
  await tab.getByRole('button', { name: `Rename ${from}` }).first().click();
  await tab.getByLabel('New name', { exact: true }).fill(to);
  await tab.getByRole('button', { name: 'Rename', exact: true }).click();
});

Then('the machine {string} appears here without a reload', async function (name) {
  await assert.seeText(this.page, name, { exact: true });
  const probe = await this.page.evaluate(() => window.__liveProbe);
  if (probe !== 'kept') {
    throw new Error('The page reloaded; the stream did not update it in place.');
  }
});

/**
 * Opens the machines URL twice — once as the plain JSON call, once as a live
 * stream — and renames a machine through the page's own session, capturing what
 * the stream pushed. Runs entirely in the page so the session cookie and CSRF
 * cookie are the real ones.
 */
When(
  'I stream the machines URL and rename {string} to {string}',
  async function (from, to) {
    const result = await this.page.evaluate(
      async ({ from, to }) => {
        const cookie = (name) =>
          document.cookie
            .split('; ')
            .find((entry) => entry.startsWith(`${name}=`))
            ?.split('=')[1] ?? '';

        const once = await (await fetch('/api/account/machines')).json();

        const source = new EventSource('/api/account/machines');
        const waitFor = (predicate) =>
          new Promise((resolve, reject) => {
            const timer = setTimeout(
              () => reject(new Error('Timed out waiting for a matching frame.')),
              10_000
            );
            source.onmessage = (event) => {
              const data = JSON.parse(event.data);
              if (predicate(data)) {
                clearTimeout(timer);
                resolve(data);
              }
            };
            source.onerror = () => {
              clearTimeout(timer);
              reject(new Error('The stream errored.'));
            };
          });

        const first = await waitFor(() => true);
        const id = once.machines.find((machine) => machine.name === from).id;
        const response = await fetch(`/api/account/machines/${id}/rename`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-csrf-token': cookie('__Host-weaver_csrf')
          },
          body: JSON.stringify({ name: to })
        });
        const updated = await waitFor((page) =>
          page.machines.some((machine) => machine.name === to)
        );
        source.close();

        return {
          ok: response.ok,
          once: once.machines.map((machine) => machine.name),
          first: first.machines.map((machine) => machine.name),
          updated: updated.machines.map((machine) => machine.name)
        };
      },
      { from, to }
    );
    this.live = { from, to, ...result };
  }
);

Then("the stream's first frame matches the JSON call", function () {
  const { ok, once, first } = this.live;
  if (!ok) {
    throw new Error('The rename request behind the stream was refused.');
  }
  if (JSON.stringify(once) !== JSON.stringify(first)) {
    throw new Error(
      `The stream's first frame did not match the JSON call:\n  once:  ${JSON.stringify(once)}\n  first: ${JSON.stringify(first)}`
    );
  }
});

Then('a later frame carries {string}', function (name) {
  const { from, updated } = this.live;
  if (!updated.includes(name)) {
    throw new Error(`No pushed frame carried "${name}"; frames showed ${JSON.stringify(updated)}.`);
  }
  if (updated.includes(from)) {
    throw new Error(`A pushed frame still carried the old name "${from}".`);
  }
});
