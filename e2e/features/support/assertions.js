/**
 * Small, loud assertions layered on Playwright's own auto-waiting.
 *
 * The `playwright` package has no `expect`; these helpers wrap `locator.waitFor`
 * so a miss fails with the page URL, title and the locator that was expected —
 * enough to debug from CI output alone. No arbitrary sleeps: every assertion is
 * a real visibility wait.
 */

const DEFAULT_TIMEOUT = 20_000;

/** Waits for `locator` to become visible, else throws a context-rich error. */
async function waitVisible(page, locator, description) {
  try {
    await locator.waitFor({ state: 'visible', timeout: DEFAULT_TIMEOUT });
  } catch (error) {
    const url = page.url();
    const title = await page.title().catch(() => '');
    throw new Error(
      `Expected to see ${description}, but it did not become visible.\n` +
        `  url:   ${url}\n` +
        `  title: ${title}\n` +
        `  cause: ${error.message}`
    );
  }
}

/** An exact-text heading. */
export async function seeHeading(page, name) {
  await waitVisible(page, page.getByRole('heading', { name, exact: true }), `heading "${name}"`);
}

/** An exact-text link. Uses `.first()` because CTAs repeat across the page. */
export async function seeLink(page, name) {
  await waitVisible(page, page.getByRole('link', { name, exact: true }).first(), `link "${name}"`);
}

/** Text appearing anywhere on the page. */
export async function seeText(page, text, { exact = false } = {}) {
  await waitVisible(page, page.getByText(text, { exact }).first(), `text "${text}"`);
}

/** An ARIA alert containing `text`. */
export async function seeAlert(page, text) {
  await waitVisible(
    page,
    page.getByRole('alert').filter({ hasText: text }),
    `alert containing "${text}"`
  );
}

/** A `<dd>` (ARIA `definition`) whose text contains `text`. */
export async function seeDefinition(page, text) {
  await waitVisible(
    page,
    page.getByRole('definition').filter({ hasText: text }).first(),
    `definition containing "${text}"`
  );
}

/** A labelled ARIA region — a `<section aria-labelledby>` named from its heading. */
export async function seeRegion(page, name) {
  await waitVisible(page, page.getByRole('region', { name, exact: true }), `region "${name}"`);
}

/** A form control carrying an exact accessible label. */
export async function seeLabel(page, name) {
  await waitVisible(page, page.getByLabel(name, { exact: true }), `field labelled "${name}"`);
}

/** Asserts a field's current value, failing with both values in the message. */
export async function seeFieldValue(page, locator, expected, description) {
  await waitVisible(page, locator, description);
  const actual = await locator.inputValue();
  if (actual !== expected) {
    throw new Error(
      `Expected ${description} to be "${expected}", but it was "${actual}".\n` +
        `  url: ${page.url()}`
    );
  }
}
