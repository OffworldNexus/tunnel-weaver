// Inline assets imported as build-time text (Vite's `?raw` suffix).
// Kept in its own ambient file because `app.d.ts` is a module (`export {}`),
// where a wildcard module declaration is not allowed.
declare module '*.svg?raw' {
	const content: string;
	export default content;
}
