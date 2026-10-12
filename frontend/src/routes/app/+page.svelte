<script lang="ts">
	/**
	 * The account overview, under the signed-in shell.
	 *
	 * The `/app` layout has already confirmed the session and published the
	 * identity, so this page only renders it. Sign-out is CSRF-protected and
	 * needs the double-submit cookie.
	 */
	import { goto } from '$app/navigation';
	import { api, messageOf } from '#lib/account/api';
	import { networkError, notify } from '#lib/account/notices';
	import { csrfToken } from '#lib/account/session';
	import { me } from '#lib/app/me';
	import { href } from '#lib/app/paths';
	import Keycap from '#lib/ui/Keycap.svelte';

	let signingOut = false;
	let error = '';

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

<h1 id="app-title">Your account</h1>

{#if $me}
	<p class="lede">
		{$me.name}{#if $me.email}<span aria-hidden="true"> · </span>{$me.email}{/if}
	</p>

	<dl class="identity">
		<div>
			<dt>Name</dt>
			<dd>{$me.name}</dd>
		</div>
		<div>
			<dt>Email</dt>
			<dd>{$me.email ?? '—'}</dd>
		</div>
		<div>
			<dt>Account ID</dt>
			<dd>{$me.id}</dd>
		</div>
	</dl>

	{#if error}
		<p class="notice-error" role="alert" aria-live="assertive" style="margin-top:20px">{error}</p>
	{/if}

	<div class="actions">
		<Keycap type="button" loading={signingOut} onclick={signOut} wide>Sign out</Keycap>
	</div>
{/if}

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
