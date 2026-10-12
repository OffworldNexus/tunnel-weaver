/**
 * Cucumber configuration for the account-relay end-to-end suite.
 *
 * Support modules load before step definitions so the custom World and the
 * Before/After hooks are registered first. Paths are relative to this file's
 * directory (the `e2e/` package), which is where `cucumber-js` is invoked.
 */
export default {
  paths: ['features/**/*.feature'],
  import: [
    'features/support/world.js',
    'features/support/hooks.js',
    'features/step_definitions/**/*.js'
  ],
  format: ['progress-bar', 'summary'],
  parallel: 1,
  retry: 0,
  publish: false
};
