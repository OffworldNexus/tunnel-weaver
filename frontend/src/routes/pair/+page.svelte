<script lang="ts">
	/**
	 * Approves a machine pairing.
	 *
	 * The handle rides in the URL fragment (`/pair#handle=<hex>`), so it never
	 * reaches an access log or a `Referer`. On mount it is read, stripped from the
	 * address bar, remembered (a detour through sign-in would lose the fragment),
	 * and exchanged for the pending request.
	 *
	 * A **new machine** has a name — and, on a first pairing, a person slug —
	 * the person may edit. An **existing machine** whose key was lost has fixed
	 * names: the person only confirms that it moves onto the new key.
	 *
	 * This is a fragment-carried, one-shot workflow, not a load: the handle rides
	 * in the URL fragment and is exchanged here (and may detour through sign-in),
	 * so it stays an explicit one-shot effect rather than a route loader — a
	 * loader could re-run and would have to answer again about a workflow that is
	 * already spent. `untrack` keeps it from ever re-running.
	 */
	import { untrack } from 'svelte';

	import { api, type RefusalHandler } from '#lib/account/api';
	import { pairing } from '#lib/account/state';
	import { fingerprint } from '#lib/app/fingerprint';
	import { atLeast, useSession } from '#lib/app/session.svelte';
	import { climb } from '#lib/app/upgrade';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	interface Proposed {
		name: string;
		/** Approving creates it, so the name is editable. */
		is_new: boolean;
	}
	type Lookup =
		| {
				state: 'waiting';
				fingerprint: string;
				account: string;
				person: Proposed;
				machine: Proposed;
		  }
		| { state: 'not_your_machine' }
		| { state: 'gone' };

	let phase = $state<'checking' | 'form' | 'not-yours' | 'gone' | 'done' | 'rejected' | 'error'>(
		'checking'
	);
	let handle = $state('');
	let request = $state<Extract<Lookup, { state: 'waiting' }> | null>(null);
	let personSlug = $state('');
	let machineName = $state('');
	let message = $state('');
	let busy = $state(false);

	const session = useSession();

	/**
	 * A refusal mid-approval (the level dropped since the page opened): keep
	 * the detour, so the approval resumes here once the person is back up.
	 */
	const resumeAfterClimb: RefusalHandler = async (required, options) => {
		pairing.save({ detour: true });
		await climb(required, options);
	};

	async function load(): Promise<void> {
		phase = 'checking';
		handle =
			new URLSearchParams(location.hash.slice(1)).get('handle') ?? pairing.load().handle ?? '';
		if (!handle) {
			phase = 'gone';
			return;
		}
		pairing.save({ handle, detour: undefined });
		void goto(resolve('/pair'), { replace: true, shallow: true });

		// The root layout holds until the session stream's first frame. Approving
		// needs `strong`: anyone below it is sent up the path the stream names —
		// sign-in for a visitor, the code step for a password-only session —
		// keeping the detour so the approval resumes here (WVR-167).
		if (!atLeast(session.level, 'strong')) {
			pairing.save({ detour: true });
			await climb('strong');
			return;
		}

		const res = await api<Lookup>('POST', '/api/account/pair/lookup', { handle }, resumeAfterClimb);
		if (!res.ok || !res.data) {
			message = res.error ?? 'We could not check this pairing request.';
			phase = 'error';
		} else if (res.data.state === 'waiting') {
			request = res.data;
			personSlug = request.person.name;
			machineName = request.machine.name;
			phase = 'form';
		} else if (res.data.state === 'not_your_machine') {
			phase = 'not-yours';
		} else {
			pairing.clear();
			phase = 'gone';
		}
	}

	$effect(() => {
		untrack(() => {
			void load();
		});
	});

	/** Runs a verdict. A refused accept leaves the request waiting, so the form stays. */
	async function act(path: string, body: object, success: 'done' | 'rejected'): Promise<void> {
		busy = true;
		message = '';
		const res = await api<{ ok: boolean; message?: string }>(
			'POST',
			path,
			{ handle, ...body },
			resumeAfterClimb
		);
		busy = false;
		if (res.data?.ok) {
			pairing.clear();
			phase = success;
		} else {
			message = res.data?.message ?? res.error ?? 'We could not complete this pairing.';
		}
	}

	const accept = () =>
		act(
			'/api/account/pair/accept',
			{
				...(request?.person.is_new ? { person_slug: personSlug } : {}),
				...(request?.machine.is_new ? { machine_name: machineName } : {})
			},
			'done'
		);
	const reject = () => act('/api/account/pair/reject', {}, 'rejected');
</script>

<svelte:head>
	<title>Approve a machine · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="pair-title">
	{#if phase === 'checking'}
		<h1 id="pair-title">Approve a machine</h1>
		<p class="lede" role="status">Checking the pairing request…</p>
	{:else if phase === 'form' && request}
		{#if request.machine.is_new}
			<h1 id="pair-title">Approve a machine</h1>
			<p class="lede">
				A machine wants to connect as <strong>{request.account}</strong>. Approving it lets its
				device key serve tunnels under your account.
			</p>

			<div class="form">
				<div class="field">
					<label for="machine">Machine name</label>
					<input id="machine" name="machine" type="text" bind:value={machineName} disabled={busy} />
				</div>

				{#if request.person.is_new}
					<div class="field">
						<label for="person">Person slug</label>
						<input id="person" name="person" type="text" bind:value={personSlug} disabled={busy} />
					</div>
				{/if}
			</div>
		{:else}
			<h1 id="pair-title">Move a machine to a new key</h1>
			<p class="lede">
				<strong>{request.person.name}/{request.machine.name}</strong> lost its device key and asks to
				continue with a new one. Its name and its tunnels stay the same; the old key stops working.
			</p>
		{/if}

		<p class="fingerprint">
			New key fingerprint<br />
			<code>{fingerprint(request.fingerprint)}</code>
		</p>

		<div class="actions">
			{#if message}<p class="notice-error" role="alert">{message}</p>{/if}
			<Keycap loading={busy} disabled={busy} onclick={accept}>
				{request.machine.is_new ? 'Approve this machine' : 'Use the new key'}
			</Keycap>
			<Keycap variant="ghost" disabled={busy} onclick={reject}>Reject</Keycap>
		</div>
	{:else if phase === 'not-yours'}
		<h1 id="pair-title">Not one of your machines</h1>
		<p class="lede">
			This request is for a machine that does not belong to your account. You can only reject it.
		</p>
		<div class="actions">
			{#if message}<p class="notice-error" role="alert">{message}</p>{/if}
			<Keycap variant="ghost" disabled={busy} onclick={reject}>Reject</Keycap>
		</div>
	{:else if phase === 'done'}
		<h1 id="pair-title">Machine approved</h1>
		<p class="lede">
			The machine is paired. Back in the terminal, it will print the hostnames it serves.
		</p>
		<div class="actions">
			<Keycap href={resolve('/app')} wide>Go to your account</Keycap>
		</div>
	{:else if phase === 'rejected'}
		<h1 id="pair-title">Pairing rejected</h1>
		<p class="lede">The machine was not approved. Re-run <code>weave pair</code> to try again.</p>
		<div class="actions">
			<Keycap href={resolve('/app')} variant="ghost" wide>Go to your account</Keycap>
		</div>
	{:else if phase === 'gone'}
		<h1 id="pair-title">Request no longer waiting</h1>
		<p class="lede">
			This pairing is no longer available — the terminal stopped waiting. Re-run
			<code>weave pair</code> and open the new link.
		</p>
	{:else}
		<h1 id="pair-title">Something went wrong</h1>
		<p class="lede">{message}</p>
		<div class="actions">
			<Keycap type="button" variant="ghost" onclick={load} wide>Try again</Keycap>
		</div>
	{/if}
</Page>

<style lang="scss">
	/* Names are short lowercase ASCII labels; the mono face keeps them legible. */
	.field input,
	.fingerprint code {
		font-family: var(--tw-mono);
	}

	.fingerprint {
		margin-top: 16px;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.5;
	}

	.fingerprint code {
		font-size: 13px;
		word-break: break-all;
	}
</style>
