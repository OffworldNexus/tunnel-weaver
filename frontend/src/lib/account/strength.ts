/**
 * Password-strength estimation for the "New password" meter, backed by zxcvbn.
 *
 * Display only: the relay owns the real policy (a minimum length plus a breach
 * check) and decides on submit, so a "Strong" rating here is never a promise
 * that the password will be accepted.
 *
 * zxcvbn and its dictionaries weigh several hundred kilobytes, so they are
 * fetched on first use (see {@link loadEstimator}) rather than shipped in the
 * initial bundle.
 */

export interface Estimate {
	/** zxcvbn's score: 0 (trivially guessable) to 4 (very unguessable). */
	score: 0 | 1 | 2 | 3 | 4;
	/** What makes the password weak, or empty when nothing stands out. */
	warning: string;
	/** How to make it stronger; empty when zxcvbn has nothing to add. */
	suggestions: string[];
}

export type Estimator = (password: string) => Estimate;

let loading: Promise<Estimator> | undefined;

/** Loads zxcvbn with the common and English packs, once; later calls share it. */
export function loadEstimator(): Promise<Estimator> {
	loading ??= build().catch((error: unknown) => {
		// A failed fetch (offline, a deploy swapped the chunks) must not stick.
		loading = undefined;
		throw error;
	});
	return loading;
}

async function build(): Promise<Estimator> {
	const [{ ZxcvbnFactory }, common, en] = await Promise.all([
		import('@zxcvbn-ts/core'),
		import('@zxcvbn-ts/language-common'),
		import('@zxcvbn-ts/language-en')
	]);
	const zxcvbn = new ZxcvbnFactory({
		dictionary: { ...common.dictionary, ...en.dictionary },
		graphs: common.adjacencyGraphs,
		translations: en.translations
	});
	return (password) => {
		const { score, feedback } = zxcvbn.check(password);
		return { score, warning: feedback.warning ?? '', suggestions: feedback.suggestions };
	};
}
