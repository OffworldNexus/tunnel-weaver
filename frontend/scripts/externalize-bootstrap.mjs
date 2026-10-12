// Moves SvelteKit's inline bootstrap `<script>` out of `build/index.html` and
// into a same-origin module under the base path.
//
// The relay's CSP is `script-src 'self'` with no nonce or hash, and the edge
// cannot be changed, so an inline bootstrap would be blocked and the app would
// never boot. SvelteKit emits that bootstrap inline for SPA fallbacks; this
// step rewrites it in place to `<script src="…">`, which stays inside
// `script-src 'self'` and lives under `{base}/_app/immutable/entry/`.
//
// The bootstrap uses `document.currentScript.parentElement` to find its
// hydration target, so it must remain a classic script directly in `<body>`
// (module scripts have a null `currentScript`). Its imports are absolute, so
// relocating the file does not break them.

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const buildDir = fileURLToPath(new URL('../build/', import.meta.url));
const indexPath = join(buildDir, 'index.html');
const outDir = join(buildDir, '_app', 'immutable', 'entry');

let html = readFileSync(indexPath, 'utf8');

const inlineScript = /<script(?![^>]*\bsrc=)([^>]*)>([\s\S]*?)<\/script>/g;
const written = [];

html = html.replace(inlineScript, (match, attrs, body) => {
	if (!body.trim()) return match;

	// Recover the configured base path from the bootstrap's absolute imports.
	const baseMatch = body.match(/["']([^"']*)\/_app\/immutable\/entry\/start/);
	const base = baseMatch ? baseMatch[1] : '';

	const hash = createHash('sha256').update(body).digest('hex').slice(0, 12);
	const name = `bootstrap.${hash}.js`;
	mkdirSync(outDir, { recursive: true });
	writeFileSync(join(outDir, name), body.replace(/^[\r\n]+/, '').replace(/\s+$/, '\n'));
	written.push(name);

	return `<script${attrs} src="${base}/_app/immutable/entry/${name}"></script>`;
});

if (written.length === 0) {
	console.log('externalize-bootstrap: no inline scripts found (nothing to do)');
	process.exit(0);
}

writeFileSync(indexPath, html);
console.log(`externalize-bootstrap: externalized ${written.join(', ')}`);
