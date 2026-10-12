// See https://svelte.dev/docs/kit/types#app
declare global {
	/** The ALTCHA widget sets this global once its module has executed. */
	var $altcha:
		| {
				algorithms?: {
					set?: (name: string, factory: () => Worker) => void;
				};
				i18n?: {
					get?: (code: string) => Record<string, string> | undefined;
					set?: (code: string, map: Record<string, string>) => void;
				};
		  }
		| undefined;

	namespace App {
		// interface Error {}
		// interface Locals {}
		// interface PageData {}
		// interface PageState {}
		// interface Platform {}
	}
}

export {};
