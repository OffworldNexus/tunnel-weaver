<script lang="ts">
	/**
	 * Signed-in shell.
	 *
	 * Confirms the session with the relay on mount (`GET /api/account/me`) and
	 * shows the identity it returns. A 401 means the session is gone, not a
	 * failure: notify and send the user back to sign-in. Sign-out is
	 * CSRF-protected, so it needs the double-submit cookie.
	 */

	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { api, messageOf } from '#lib/account/api';
	import { networkError, notify, sessionExpired } from '#lib/account/notices';
	import { csrfToken } from '#lib/account/session';
	import { href } from '#lib/app/paths';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Page from '#lib/ui/Page.svelte';

	interface Me {
		id: number | string;
		name: string;
		email: string | null;
	}

	let me: Me | null = null;
	let checking = true;
	let authenticated = false;
	let authStatus = 'Checking your session…';
	let error = '';
	let signingOut = false;

	onMount(() => {
		check();
	});

	// Load the signed-in identity on entry; a 401 is a stale session, not an error.
	async function check() {
		checking = true;
		error = '';
		authStatus = 'Checking your session…';
		try {
			const result = await api<Me>('/api/account/me');
			if (result.ok && result.data) {
				me = result.data;
				authenticated = true;
				authStatus = 'Authenticated';
			} else if (result.status === 401) {
				sessionExpired();
				await goto(href('/sign-in'));
			} else {
				authenticated = false;
				authStatus = 'Not verified';
				error = messageOf(result.data, 'We could not verify your session. Try again.');
			}
		} catch {
			authenticated = false;
			authStatus = 'Not verified';
			error = 'We could not reach the server.';
			networkError();
		} finally {
			checking = false;
		}
	}

	// Logout is CSRF-protected: without the cookie we refuse locally rather than
	// send a request the relay would reject anyway.
	async function signOut() {
		if (signingOut) return;
		error = '';
		const csrf = csrfToken();
		if (!csrf) {
			error = 'We could not sign you out safely. Reload the page and try again.';
			return;
		}
		signingOut = true;
		try {
			const result = await api('/api/account/logout', { method: 'POST', csrf });
			if (result.ok) {
				notify('success', 'You have been signed out.');
				await goto(href('/sign-in'));
			} else {
				error = messageOf(result.data, 'We could not sign you out. Please try again.');
			}
		} catch {
			networkError();
		} finally {
			signingOut = false;
		}
	}
</script>

<svelte:head>
	<title>Your account · Tunnel Weaver</title>
</svelte:head>

<Page center={false} labelledby="app-title">
	<h1 id="app-title">Your account</h1>

	{#if me}
		<!-- Confirmed session: the identity the relay reported. -->
		<p class="lede">
			{me.name}{#if me.email}<span aria-hidden="true"> · </span>{me.email}{/if}
		</p>

		<dl class="identity">
			<div>
				<dt>Name</dt>
				<dd>{me.name}</dd>
			</div>
			<div>
				<dt>Email</dt>
				<dd>{me.email ?? '—'}</dd>
			</div>
			<div>
				<dt>Account ID</dt>
				<dd>{me.id}</dd>
			</div>
			<div>
				<dt>Authentication</dt>
				<dd aria-live="polite">{authStatus}</dd>
			</div>
		</dl>

		{#if error}
			<p class="notice-error" role="alert" aria-live="assertive" style="margin-top:20px">{error}</p>
		{/if}

		<div class="actions">
			<Keycap type="button" loading={signingOut} onclick={signOut} wide>Sign out</Keycap>
			<Keycap type="button" variant="ghost" loading={checking} onclick={check} wide>
				Check authentication
			</Keycap>
		</div>
	{:else}
		<!-- Not confirmed (still checking, or the session was rejected): offer a retry. -->
		<p class="lede" aria-live="polite">
			{#if checking}Checking your session…{:else}You are not signed in.{/if}
		</p>
		{#if error}
			<p class="notice-error" role="alert" aria-live="assertive">{error}</p>
		{/if}
		<div class="actions">
			<Keycap type="button" loading={checking} onclick={check} wide>Check authentication</Keycap>
			<Keycap wide variant="ghost" href={href('/sign-in')}>Back to sign in</Keycap>
		</div>
	{/if}
</Page>

<style lang="scss">
	.identity {
		display: grid;
		gap: 0;
		margin: 24px 0 0;
		padding: 0;
		border-top: 1.5px solid var(--tw-border);
	}

	.identity div {
		display: flex;
		justify-content: space-between;
		gap: 16px;
		padding: 12px 0;
		border-bottom: 1.5px solid var(--tw-border);
	}

	.identity dt {
		margin: 0;
		color: var(--tw-muted);
		font-size: 14px;
		font-weight: 700;
	}

	.identity dd {
		margin: 0;
		font-weight: 700;
		text-align: right;
		overflow-wrap: anywhere;
	}
</style>
