<script lang="ts">
	/**
	 * Approve a machine pairing.
	 *
	 * The handle rides in the URL fragment (`/pair#handle=<hex>`), never the
	 * query, so it cannot reach an access log or a `Referer`. On mount it is
	 * read, stripped from the address bar, remembered (a detour through sign-in
	 * would otherwise lose the fragment), and exchanged for the pending request.
	 *
	 * Two shapes of request exist. A **new machine**: its name — and, on a first
	 * pairing, the person slug — are proposals the person may edit. An **existing
	 * machine** whose key was lost: everything is fixed, the person only confirms
	 * that the machine moves onto the new key.
	 */
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { api } from '#lib/account/api';
	import { clearPairing, loadPairing, savePairing } from '#lib/account/pairing';
	import { csrfToken } from '#lib/account/session';
	import { ensureMe } from '#lib/app/me';
	import { href } from '#lib/app/paths';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';

	interface Proposed {
		name: string;
		/** `true`: approving creates it and the name is editable. */
		is_new: boolean;
	}
	type Lookup =
		| { state: 'waiting'; fingerprint: string; account: string; person: Proposed; machine: Proposed }
		| { state: 'not_your_machine' }
		| { state: 'gone' };

	type Phase = 'checking' | 'form' | 'not-yours' | 'gone' | 'done' | 'rejected' | 'error';

	let phase: Phase = 'checking';
	let handle = '';
	let fingerprint = '';
	let account = '';
	let personSlug = '';
	let personIsNew = false;
	let machineName = '';
	let machineIsNew = true;
	let message = '';
	let busy = false;

	/** Reads the handle out of the URL fragment (never the query string). */
	function readHandle(): string {
		if (typeof window === 'undefined') return '';
		return new URLSearchParams(window.location.hash.replace(/^#/, '')).get('handle') ?? '';
	}

	onMount(async () => {
		handle = readHandle() || loadPairing().handle || '';
		if (!handle) {
			phase = 'gone';
			return;
		}
		savePairing({ handle });
		void goto(href('/pair'), { replace: true, shallow: true });

		const session = await ensureMe();
		if (session.status === 'unauthenticated') {
			savePairing({ next: '/pair' });
			await goto(href('/sign-in'));
			return;
		}
		if (session.status === 'error') {
			message = session.message;
			phase = 'error';
			return;
		}
		await lookup();
	});

	async function lookup(): Promise<void> {
		try {
			const res = await api<Lookup>('/api/account/pair/lookup', {
				method: 'POST',
				body: { handle }
			});
			if (res.ok && res.data?.state === 'waiting') {
				fingerprint = res.data.fingerprint;
				account = res.data.account;
				personSlug = res.data.person.name;
				personIsNew = res.data.person.is_new;
				machineName = res.data.machine.name;
				machineIsNew = res.data.machine.is_new;
				phase = 'form';
				return;
			}
			if (res.ok && res.data?.state === 'not_your_machine') {
				phase = 'not-yours';
				return;
			}
		} catch {
			// An unreachable relay reads as "no longer waiting": re-running
			// `weave pair` recovers.
		}
		phase = 'gone';
	}

	async function accept(): Promise<void> {
		busy = true;
		message = '';
		try {
			const res = await api<{ ok: boolean; message?: string }>('/api/account/pair/accept', {
				method: 'POST',
				csrf: csrfToken(),
				body: {
					handle,
					...(personIsNew ? { person_slug: personSlug } : {}),
					...(machineIsNew ? { machine_name: machineName } : {})
				}
			});
			clearPairing();
			if (res.ok && res.data?.ok) {
				phase = 'done';
				return;
			}
			// The handle is single use: a refusal cannot be retried from here.
			if (res.data?.message) {
				message = res.data.message;
				phase = 'error';
			} else {
				phase = 'gone';
			}
		} catch {
			message = 'We could not reach the server. Check your connection and try again.';
		} finally {
			busy = false;
		}
	}

	async function reject(): Promise<void> {
		busy = true;
		try {
			await api('/api/account/pair/reject', {
				method: 'POST',
				csrf: csrfToken(),
				body: { handle }
			});
			clearPairing();
			phase = 'rejected';
		} catch {
			message = 'We could not reach the server. Check your connection and try again.';
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head>
	<title>Approve a machine · Tunnel Weaver</title>
</svelte:head>

<Page labelledby="pair-title">
	{#if phase === 'checking'}
		<h1 id="pair-title">Approve a machine</h1>
		<p class="lede" role="status" aria-live="polite">Checking the pairing request…</p>
	{:else if phase === 'form'}
		{#if machineIsNew}
			<h1 id="pair-title">Approve a machine</h1>
			<p class="lede">
				A machine wants to connect as <strong>{account}</strong>. Approving it lets its device
				key serve tunnels under your account.
			</p>

			<div class="field">
				<label for="machine">Machine name</label>
				<input id="machine" name="machine" type="text" bind:value={machineName} disabled={busy} />
			</div>

			{#if personIsNew}
				<div class="field">
					<label for="person">Person slug</label>
					<input id="person" name="person" type="text" bind:value={personSlug} disabled={busy} />
				</div>
			{/if}
		{:else}
			<h1 id="pair-title">Move a machine to a new key</h1>
			<p class="lede">
				<strong>{personSlug}/{machineName}</strong> lost its device key and asks to continue
				with a new one. Its name and its tunnels stay the same; the old key stops working.
			</p>
		{/if}

		<p class="fingerprint">
			New key fingerprint<br />
			<code>{fingerprint}</code>
		</p>

		{#if message}
			<p class="notice-error" role="alert" aria-live="assertive">{message}</p>
		{/if}

		<div class="actions">
			<Keycap loading={busy} disabled={busy} onclick={accept}>
				{machineIsNew ? 'Approve this machine' : 'Use the new key'}
			</Keycap>
			<Keycap variant="ghost" disabled={busy} onclick={reject}>Reject</Keycap>
		</div>
	{:else if phase === 'not-yours'}
		<h1 id="pair-title">Not one of your machines</h1>
		<p class="lede">
			This request is for a machine that does not belong to your account. You can only reject
			it.
		</p>
		<div class="actions">
			<Keycap variant="ghost" disabled={busy} onclick={reject}>Reject</Keycap>
		</div>
	{:else if phase === 'done'}
		<h1 id="pair-title">Machine approved</h1>
		<p class="lede">
			<strong>{machineName}</strong> is paired. Back in the terminal, it will print the hostnames
			it serves.
		</p>
		<div class="actions">
			<Keycap href={href('/app')} wide>Go to your account</Keycap>
		</div>
	{:else if phase === 'rejected'}
		<h1 id="pair-title">Pairing rejected</h1>
		<p class="lede">The machine was not approved. Re-run <code>weave pair</code> to try again.</p>
		<div class="actions">
			<Keycap href={href('/app')} variant="ghost" wide>Go to your account</Keycap>
		</div>
	{:else if phase === 'gone'}
		<h1 id="pair-title">Request no longer waiting</h1>
		<p class="lede">
			This pairing is no longer available — the terminal stopped waiting. Re-run
			<code>weave pair</code> and open the new link.
		</p>
	{:else}
		<h1 id="pair-title">Something went wrong</h1>
		<p class="lede">{message || 'We could not check this pairing request.'}</p>
		<div class="actions">
			<Keycap href={href('/pair')} variant="ghost" wide>Try again</Keycap>
		</div>
	{/if}
</Page>

<style lang="scss">
	/* A machine name and a person slug are short, ASCII, and lowercased; the
	   mono face makes the two-label shape (person-machine) legible. */
	.field {
		display: flex;
		flex-direction: column;
		gap: 6px;
		margin-top: 16px;
	}

	.field label {
		color: var(--tw-muted);
		font-size: 14px;
	}

	.field input {
		min-height: 44px;
		padding: 0 14px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
		color: var(--tw-text);
		font: 400 16px/1 var(--tw-mono);
	}

	.fingerprint {
		margin-top: 16px;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.5;
	}

	.fingerprint code {
		font-family: var(--tw-mono);
		font-size: 13px;
		word-break: break-all;
	}

	.actions {
		display: flex;
		flex-direction: column;
		gap: 12px;
		margin-top: 20px;
	}

	.notice-error {
		margin-top: 12px;
		color: var(--tw-danger, #b42318);
		font-size: 14px;
	}
</style>
