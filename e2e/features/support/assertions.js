/**
 * Assertions over Playwright's auto-waiting (the `playwright` package has no
 * `expect`). A miss fails with the page URL, enough to debug from CI output.
 */

async function waitVisible(page, locator, description) {
  try {
    await locator.waitFor({ state: 'visible' });
  } catch (error) {
    throw new Error(`Expected to see ${description} at ${page.url()}.\n  cause: ${error.message}`);
  }
}

export const seeHeading = (page, name) =>
  waitVisible(page, page.getByRole('heading', { name, exact: true }), `the heading "${name}"`);

export const seeLink = (page, name) =>
  waitVisible(page, page.getByRole('link', { name, exact: true }).first(), `the link "${name}"`);

export const seeText = (page, text, { exact = false } = {}) =>
  waitVisible(page, page.getByText(text, { exact }).first(), `the text "${text}"`);

export const seeAlert = (page, text) =>
  waitVisible(page, page.getByRole('alert').filter({ hasText: text }), `an alert with "${text}"`);

export const seeDefinition = (page, text) =>
  waitVisible(
    page,
    page.getByRole('definition').filter({ hasText: text }).first(),
    `a definition with "${text}"`
  );

export async function seeFieldValue(page, label, expected) {
  const field = page.getByLabel(label, { exact: true });
  await waitVisible(page, field, `the field "${label}"`);
  const actual = await field.inputValue();
  if (actual !== expected) {
    throw new Error(`Expected the field "${label}" to hold "${expected}", but it held "${actual}".`);
  }
}

export async function seeNoField(page, label) {
  const count = await page.getByLabel(label, { exact: true }).count();
  if (count !== 0) throw new Error(`Expected no field "${label}" at ${page.url()}.`);
}
