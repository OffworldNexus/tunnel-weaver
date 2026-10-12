// SPA mode: no server rendering (the relay serves a static shell) and no
// prerendering (every history route is handled client-side and rewritten to
// `index.html` by the edge).
export const ssr = false;
export const prerender = false;
