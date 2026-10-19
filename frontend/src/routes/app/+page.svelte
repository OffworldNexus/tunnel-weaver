<script lang="ts">
	/** The account overview; the `/app` layout has already confirmed the session. */
	import { api } from '#lib/account/api';
	import { notify } from '#lib/account/notices';
	import { me } from '#lib/app/me';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';

	let signingOut = false;
	let error = '';

	async function signOut() {
		signingOut = true;
		error = '';
		const res = await api('/api/account/logout', {});
		signingOut = false;
		if (!res.ok) {
			error = res.error ?? 'We could not sign you out. Please try again.';
			return;
		}
		notify('success', 'You have been signed out.');
		await goto(resolve('/sign-in'));
	}
</script>

{#if $me}
	<h1 id="app-title">Your account</h1>
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
			<dd>{$me.email || '—'}</dd>
		</div>
		<div>
			<dt>Account ID</dt>
			<dd>{$me.id}</dd>
		</div>
	</dl>

	<div class="actions">
		{#if error}<p class="notice-error" role="alert">{error}</p>{/if}
		<Keycap type="button" loading={signingOut} onclick={signOut} wide>Sign out</Keycap>
	</div>
{/if}

<style lang="scss">
	.identity {
		display: grid;
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
