<script lang="ts">
	/**
	 * The "New password" field: a zxcvbn strength meter, the relay's minimum and
	 * a show/hide toggle. The meter only guides; the relay owns the real policy
	 * (a minimum length plus a breach check) and decides on submit.
	 */
	import { minPasswordLength } from '#lib/account/config';
	import { type Estimate, type Estimator, loadEstimator } from '#lib/account/strength';

	export let id: string;
	export let value: string;
	export let error: string | undefined = undefined;
	export let disabled = false;

	let show = false;

	// zxcvbn is fetched the first time the field is focused or typed into.
	let requested = false;
	// Unset until zxcvbn has loaded.
	let estimate: Estimator | undefined;

	function load(): void {
		if (requested) {
			return;
		}
		requested = true;
		loadEstimator()
			.then((estimator) => {
				estimate = estimator;
			})
			.catch(() => {
				// The meter stays blank; the next focus or keystroke retries.
				requested = false;
			});
	}

	interface Meter {
		level: 'weak' | 'fair' | 'strong';
		/** Fill percentage for the bar. */
		pct: number;
		/** Short label, or empty while there is nothing to rate. */
		label: string;
		/** The hint under the field. */
		hint: string;
	}

	const LEVELS = ['weak', 'weak', 'fair', 'strong', 'strong'] as const;
	const LABELS = { weak: 'Weak', fair: 'Fair', strong: 'Strong' } as const;

	function rate(password: string, result: Estimate, min: number): Meter {
		const advice = [result.warning, ...result.suggestions].filter((line) => line !== '').join(' ');
		if (password.length < min) {
			return {
				level: 'weak',
				pct: 20,
				label: 'Too short',
				hint: [`Use at least ${min} characters.`, advice].filter((line) => line !== '').join(' ')
			};
		}
		const level = LEVELS[result.score];
		return {
			level,
			pct: (result.score + 1) * 20,
			label: LABELS[level],
			hint: advice === '' ? defaultHint(min) : advice
		};
	}

	function defaultHint(min: number): string {
		return `Use at least ${min} characters. A longer, unique passphrase beats a short, complicated one.`;
	}

	$: meter =
		estimate && value !== ''
			? rate(value, estimate(value), $minPasswordLength)
			: { level: 'weak', pct: 0, label: '', hint: defaultHint($minPasswordLength) };
</script>

<div class="field">
	<label for={id}>New password</label>
	<input
		{id}
		name={id}
		type={show ? 'text' : 'password'}
		autocomplete="new-password"
		placeholder="Create a unique password"
		bind:value
		on:focus={load}
		on:input={load}
		{disabled}
		aria-invalid={error ? 'true' : undefined}
		aria-describedby={error ? `${id}-hint ${id}-error` : `${id}-hint`}
	/>

	<div class="strength" aria-hidden="true">
		<span class="strength__track">
			<span class="strength__fill" data-level={meter.level} style={`width:${meter.pct}%`}></span>
		</span>
		<span class="strength__label">{meter.label}</span>
	</div>

	{#if error}<p id={`${id}-error`} class="field__error" aria-live="polite">{error}</p>{/if}

	<p id={`${id}-hint`} class="hint">{meter.hint}</p>

	<button type="button" class="toggle" aria-pressed={show} on:click={() => (show = !show)}>
		{show ? 'Hide password' : 'Show password'}
	</button>
</div>

<style lang="scss">
	.strength {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.strength__track {
		flex: 1;
		height: 6px;
		border-radius: 999px;
		background: var(--tw-well);
		border: 1.5px solid var(--tw-border);
		overflow: hidden;
	}

	.strength__fill {
		display: block;
		height: 100%;
		background: var(--tw-success);
		transition: width 140ms ease;
	}

	.strength__fill[data-level='weak'] {
		background: var(--tw-danger);
	}

	.strength__label {
		min-width: 3.6rem;
		text-align: right;
		color: var(--tw-muted);
		font-size: 14px;
	}

	@media (prefers-reduced-motion: reduce) {
		.strength__fill {
			transition: none;
		}
	}
</style>
