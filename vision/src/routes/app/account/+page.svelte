<script lang="ts">
	import Badge from '#lib/console/Badge.svelte';
	import ConfirmDeleteDialog from '#lib/console/ConfirmDeleteDialog.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import { setMeta } from '#lib/console/meta';
	import { date, timeAgo } from '#lib/mock/format';
	import { ROOT } from '#lib/mock/data';
	import { current, machines, signOut } from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	setMeta({ title: 'Profile', subtitle: 'Your account and identity.', crumbs: [{ label: 'Profile' }] });

	let deleting = false;

	$: me = $current?.person;
	$: mine = $machines.filter((m) => m.personId === me?.id);

	async function deleteAccount() {
		deleting = false;
		signOut();
		await goto('/sign-in');
	}
</script>

{#if me}
	<Panel title="Identity" subtitle="How the relay knows you">
		<dl class="facts">
			<div><dt>Name</dt><dd>{me.name}</dd></div>
			<div><dt>Email</dt><dd>{me.email}</dd></div>
			<div><dt>Role</dt><dd><Badge variant="accent">{$current?.role.replace('_', ' ')}</Badge></dd></div>
			{#if $current?.org}
				<div><dt>Organisation</dt><dd>{$current.org.name}</dd></div>
			{/if}
			{#if $current?.role === 'user'}
				<div>
					<dt>Hostname pattern</dt>
					<dd class="mono">{me.slug}-&lt;machine&gt;-&lt;service&gt;.{ROOT}</dd>
				</div>
				<div><dt>Paired machines</dt><dd class="mono">{mine.length}</dd></div>
			{/if}
			<div><dt>Account ID</dt><dd class="mono">{me.id}</dd></div>
			<div><dt>Joined</dt><dd>{date(me.createdAt)}</dd></div>
			<div><dt>Last seen</dt><dd>{timeAgo(me.lastSeenAt)}</dd></div>
		</dl>
	</Panel>

	<Panel title="Danger zone" subtitle="Irreversible actions">
		<div class="danger">
			<div>
				<p class="danger__title">Delete account</p>
				<p class="muted">
					Removes your account{#if $current?.role === 'user'}, unpairs every machine and stops all hostnames{/if}. This cannot be undone.
				</p>
			</div>
			<Keycap type="button" variant="danger" onclick={() => (deleting = true)}>
				<Icon name="trash" size={15} /> Delete account
			</Keycap>
		</div>
	</Panel>
{/if}

<ConfirmDeleteDialog
	bind:open={deleting}
	title="Delete your account?"
	expected={me?.email ?? ''}
	confirmLabel="Delete account"
	cancelLabel="Keep account"
	onConfirm={deleteAccount}
>
	<p>
		This permanently deletes your account{#if $current?.role === 'user'} and unpairs every machine{/if}.
	</p>
</ConfirmDeleteDialog>

<style lang="scss">
	.facts {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
		gap: 14px 22px;
		margin: 0;
	}

	.facts dt {
		font-size: 11px;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.facts dd {
		margin: 3px 0 0;
		font-size: 14px;
		overflow-wrap: anywhere;
	}

	.danger {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
	}

	.danger__title {
		font-weight: 700;
		margin-bottom: 2px;
	}
</style>
