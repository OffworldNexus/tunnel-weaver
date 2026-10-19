// See https://svelte.dev/docs/kit/types#app
declare global {
	/** Set by the ALTCHA widget once its module has executed. */
	var $altcha: { algorithms: Map<string, () => Worker> };
}

export {};
