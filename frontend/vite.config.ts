import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import { defineConfig } from 'vite';

// Superforms' `sveltekit-superforms/adapters` barrel re-exports every validation
// adapter, including ones whose optional peers are not installed. Rolldown links
// those re-exports eagerly and fails on the missing peers. We only use Valibot,
// so point the specifier straight at the Valibot adapter.
const valibotAdapter = new URL(
	'./node_modules/sveltekit-superforms/dist/adapters/valibot.js',
	import.meta.url
).pathname;

export default defineConfig({
	resolve: {
		alias: {
			'sveltekit-superforms/adapters': valibotAdapter
		}
	},
	plugins: [
		sveltekit({
			preprocess: vitePreprocess(),
			// The relay serves the account app same-origin at the admin host root, so
			// every emitted asset URL is `/_app/...`.
			paths: { base: '' },
			adapter: adapter({
				pages: 'build',
				assets: 'build',
				// SPA mode: one shell at `build/index.html` is the fallback for
				// every history route; the edge rewrites deep links to it.
				fallback: 'index.html',
				precompress: false,
				strict: false
			})
		})
	]
});
