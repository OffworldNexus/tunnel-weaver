<script lang="ts">
	/**
	 * "Try another way": every way this session can reach its second factor.
	 *
	 * The list is not decided here. A `basic` session is told, on its stream,
	 * which ways up its account actually has — one option per authentication
	 * path, in the relay's preference order — so this page describes those and
	 * performs the one that is chosen. An account with an authenticator app is
	 * offered the app's code and the emailed code; an account with no app is
	 * offered the emailed code alone; and whatever a later factor adds (backup
	 * codes, WVR-164) appears here without this page being touched.
	 *
	 * Choosing the emailed code is what *sends* one: a person who picks it is
	 * asking for a code, so the page they land on has one waiting.
	 */
	import { api } from '#lib/account/api';
	import { flow } from '#lib/account/state';
	import { useSession } from '#lib/app/session.svelte';
	import { type Step, type UpgradePath } from '#lib/app/session.svelte';
	import { climb } from '#lib/app/upgrade';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	const session = useSession();
	const verifyCode = resolve('/(auth)/verify-code');

	/** One way up, in the person's words. */
	interface Way {
		/** The step it is, as the relay named it — also its identity in the list. */
		step: Step;
		/** The option the relay offered, performed as-is for anything unfamiliar. */
		option: UpgradePath;
		label: string;
		detail: string;
		icon: 'shield' | 'inbox' | 'lock' | 'fingerprint' | 'key';
	}

	/** The step a request is in flight for; empty when none is. */
	let busy = $state<Step | ''>('');
	/** What went wrong with the last choice; empty for none. */
	let error = $state('');

	/**
	 * One option, named by the step that reaches the target at this level — the
	 * first one. A step *after* it belongs to the way up that is performed in
	 * place (the step-up popin), not to what the person is choosing here.
	 *
	 * An option this page has never heard of is still offered: its label is the
	 * relay's own step name, tidied for reading, and choosing it hands the option
	 * to the console's way-up machinery exactly as the relay wrote it. A factor
	 * that lands later (backup codes, WVR-164) is therefore usable here before
	 * anyone has written copy for it — hiding a way up because this page cannot
	 * describe it would be the worse failure.
	 */
	function describe(option: UpgradePath): Way {
		const step = option[0]?.step;
		switch (step) {
			case 'verify_totp':
				return {
					step,
					option,
					label: 'Code from your authenticator app',
					detail: 'Open your authenticator app and enter the six digits it shows.',
					icon: 'shield'
				};
			case 'verify_email_otp':
				return {
					step,
					option,
					label: 'Code by email',
					detail: `We will send a six-digit code to ${session.user?.email || 'your address'}.`,
					icon: 'inbox'
				};
			case 'confirm_password':
				return {
					step,
					option,
					label: 'Your password',
					detail: 'Type your password again to prove it is you.',
					icon: 'lock'
				};
			case 'assert_passkey':
				return {
					step,
					option,
					label: 'A passkey',
					detail: 'Use your face, fingerprint, PIN or a security key.',
					icon: 'fingerprint'
				};
			default:
				return {
					step,
					option,
					label: step.replaceAll('_', ' ').replace(/^./, (first) => first.toUpperCase()),
					detail: 'Use another way this account has set up.',
					icon: 'key'
				};
		}
	}

	/** The ways up, as the relay reports them, described for the person. */
	const ways = $derived(session.pathsTo('strong').map(describe));

	/** Takes the chosen way: send-and-go for the emailed code, name-and-go for the rest. */
	async function choose(way: Way): Promise<void> {
		if (busy !== '') {
			return;
		}
		error = '';
		// The choice travels in the flow state, not the URL: the code step reads it
		// once when it mounts, so a reload of that step keeps the choice, and it is
		// cleared once a code is accepted so the next sign-in starts on whatever
		// the relay offers rather than on last time's choice.
		flow.save({ second_factor: way.step === 'verify_totp' ? 'app' : 'email' });
		if (way.step === 'verify_totp') {
			await goto(resolve('/(auth)/verify-code'));
			return;
		}
		if (way.step === 'verify_email_otp') {
			busy = way.step;
			const res = await api<{ status: string }>('POST', '/api/account/login/resend', {}, () => {
				// A refusal here means the session is already gone, and the guard
				// will take over; there is nothing to tell the person.
			});
			busy = '';
			if (!res.ok) {
				error = res.error ?? 'We could not email you a code. Try again.';
				return;
			}
			await goto(resolve('/(auth)/verify-code'));
			return;
		}
		// A way this page does not perform itself — a step the console takes in
		// place, or one with a page of its own. The console's own machinery knows
		// what to do with it, and it is handed the option exactly as the relay
		// wrote it rather than a guess at what its steps mean.
		await climb('strong', [way.option]);
	}
</script>

<svelte:head>
	<title>Try another way · Tunnel Weaver</title>
</svelte:head>

{#if session.level === 'basic'}
	<Page labelledby="another-way-title">
		<h1 id="another-way-title">Try another way</h1>
		<p class="lede">
			Choose how to finish signing in as
			<strong>{session.user?.email || 'you'}</strong>.
		</p>

		<ul class="ways">
			{#each ways as way (way.step)}
				<li>
					<button class="way" type="button" onclick={() => choose(way)} disabled={busy !== ''}>
						<span class="way__icon"><Icon name={way.icon} size={18} /></span>
						<span class="way__copy">
							<span class="way__label">{way.label}</span>
							<span class="way__detail">{way.detail}</span>
						</span>
						{#if busy === way.step}
							<span class="way__busy" role="status">Sending…</span>
						{/if}
					</button>
				</li>
			{/each}
		</ul>

		{#if error}
			<p class="notice-error" role="alert">{error}</p>
		{/if}

		<div class="secondary">
			<Keycap href={verifyCode} variant="ghost">Back</Keycap>
		</div>
	</Page>
{/if}

<style lang="scss">
	/* One row per way up: the whole row is the button, because the person is
	   choosing a way, not reading a list of links. */
	.ways {
		list-style: none;
		margin: 24px 0 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.way {
		display: flex;
		align-items: center;
		gap: 12px;
		width: 100%;
		padding: 14px 16px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-deck);
		color: var(--tw-text);
		font: inherit;
		text-align: left;
		cursor: pointer;
	}

	.way:hover:not(:disabled) {
		border-color: var(--tw-focus);
	}

	.way:focus-visible {
		outline: 2px solid var(--tw-focus);
		outline-offset: 2px;
	}

	.way:disabled {
		cursor: progress;
		opacity: 0.75;
	}

	.way__icon {
		flex: none;
		display: flex;
		color: var(--tw-muted);
	}

	.way__copy {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
	}

	.way__label {
		font-weight: 700;
	}

	.way__detail {
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.5;
	}

	.way__busy {
		margin-left: auto;
		color: var(--tw-muted);
		font-size: 14px;
	}

	/* Two secondary actions on one line, sized to their labels, so neither reads
	   as a competing primary. */
	.secondary {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 12px;
		margin-top: 24px;
	}
</style>
