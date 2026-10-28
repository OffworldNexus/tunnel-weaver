<script lang="ts">
	/**
	 * "Try another way": every way this session can reach its second factor.
	 *
	 * The list is not decided here. A `basic` session is told, on its stream,
	 * which ways up its account actually has — one option per authentication
	 * path, in the relay's preference order — so this page describes those and
	 * performs the one that is chosen. An account with an authenticator app is
	 * offered the app's code and the emailed code; one that holds a passkey is
	 * offered that too, since an assertion is a way *in* as much as a step-up; one
	 * with neither is offered the emailed code alone; and whatever a later factor
	 * adds (backup codes, WVR-164) appears here without this page being touched.
	 *
	 * Choosing the emailed code is what *sends* one: a person who picks it is
	 * asking for a code, so the page they land on has one waiting.
	 */
	import { api } from '#lib/account/api';
	import { assertOnThisSession } from '#lib/account/passkeyAssertion';
	import { flow, pairing } from '#lib/account/state';
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
	 * How each way the console knows by name is described. One entry per step,
	 * keyed by the relay's own name; anything else falls back to the generic
	 * description below.
	 */
	const DESCRIBED: Partial<Record<Step, { label: string; detail: string; icon: Way['icon'] }>> = {
		verify_totp: {
			label: 'Code from your authenticator app',
			detail: 'Open the app and enter the six digits it shows.',
			icon: 'shield'
		},
		verify_email_otp: {
			label: 'Code by email',
			detail: `We will send a six-digit code to ${session.user?.email || 'your address'}.`,
			icon: 'inbox'
		},
		confirm_password: {
			label: 'Your password',
			detail: 'Type your password again to prove it is you.',
			icon: 'lock'
		},
		assert_passkey: {
			label: 'A passkey',
			detail: 'Use your face, fingerprint, PIN or a security key.',
			icon: 'fingerprint'
		}
	};

	/**
	 * One option, described.
	 *
	 * Named by the step that reaches the target at this level — the first one. A
	 * step *after* it belongs to the way up that is performed in place (the step-up
	 * popin), not to what the person is choosing here.
	 *
	 * A step the console has never heard of is still offered: its label is the
	 * relay's own step name, tidied for reading, and choosing it hands the option to
	 * the console's way-up machinery exactly as the relay wrote it. A factor that
	 * lands later (backup codes, WVR-164) is therefore usable here before anyone
	 * has written copy for it — hiding a way up because this page cannot describe it
	 * would be the worse failure. The one thing dropped is an option with no steps
	 * at all, which nothing could perform.
	 */
	function describe(option: UpgradePath): Way | null {
		if (option.length === 0) {
			return null;
		}
		const step = option[0].step;
		return {
			step,
			option,
			...(DESCRIBED[step] ?? {
				label: step.replaceAll('_', ' ').replace(/^./, (first) => first.toUpperCase()),
				detail: 'Use another way this account has set up.',
				icon: 'key' as const
			})
		};
	}

	/** The ways up, as the relay reports them, described for the person. */
	const ways = $derived(
		session
			.pathsTo('strong')
			.map(describe)
			.filter((way) => way !== null)
	);

	/**
	 * Takes the chosen way: send-and-go for the emailed code, in place for the
	 * rest. The passkey is performed here rather than handed to the step-up popin:
	 * the popin is for a session that is already signed in, and this one may be
	 * finishing its sign-in with the assertion itself.
	 */
	async function choose(way: Way): Promise<void> {
		if (busy !== '') {
			return;
		}
		error = '';
		// The choice travels in the flow state, not the URL: the code step reads it
		// once when it mounts, so a reload of that step keeps the choice, and it is
		// cleared once a code is accepted so the next sign-in starts on whatever
		// the relay offers rather than on last time's choice.
		const factor = FACTOR_OF[way.step];
		if (factor !== undefined) {
			flow.save({ second_factor: factor });
		}
		const performed = PERFORMED[way.step];
		if (performed === undefined) {
			// A way this page does not perform itself, handed to the console's
			// way-up machinery exactly as the relay wrote it.
			await climb('strong', [way.option]);
			return;
		}
		await performed();
	}

	/** The factor each of the code steps asks the code page for. */
	const FACTOR_OF: Partial<Record<Step, string>> = {
		verify_totp: 'app',
		verify_email_otp: 'email'
	};

	/** What choosing each way this page performs itself does. */
	const PERFORMED: Partial<Record<Step, () => Promise<void>>> = {
		verify_totp: takeAppCode,
		verify_email_otp: takeEmailCode,
		assert_passkey: takePasskey
	};

	/** The app's code: nothing to send, the code step already asks for it. */
	async function takeAppCode(): Promise<void> {
		await goto(resolve('/(auth)/verify-code'));
	}

	/** The emailed code: choosing it *is* asking for one, so it is sent here. */
	async function takeEmailCode(): Promise<void> {
		busy = 'verify_email_otp';
		const res = await api<{ status: string }>('POST', '/api/account/login/resend', {}, () => {
			// A refusal here means the session is already gone, and the guard will
			// take over; there is nothing to tell the person.
		});
		busy = '';
		if (!res.ok) {
			error = res.error ?? 'We could not email you a code. Try again.';
			return;
		}
		await goto(resolve('/(auth)/verify-code'));
	}

	/** The passkey: the assertion is performed in place, on this very session. */
	async function takePasskey(): Promise<void> {
		busy = 'assert_passkey';
		const result = await assertOnThisSession(climb);
		busy = '';
		if (result.asserted) {
			// The relay recorded the proof; the stream reports the level, and the
			// guard leaves for the console — or for the pairing detour.
			await session.reached('strong');
			await goto(resolve(pairing.load().detour ? '/pair' : '/app'));
			return;
		}
		if (!result.cancelled) {
			error = result.message !== '' ? result.message : 'That passkey was not accepted.';
		}
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
							<span class="way__busy" role="status">
								{way.step === 'assert_passkey' ? 'Waiting for your passkey…' : 'Sending…'}
							</span>
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
