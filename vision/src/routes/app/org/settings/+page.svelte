<script lang="ts">
	import ConfirmDeleteDialog from '#lib/console/ConfirmDeleteDialog.svelte';
	import Dialog from '#lib/console/Dialog.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import { setMeta } from '#lib/console/meta';
	import { notify } from '#lib/account/notices';
	import {
		activeOrg,
		clearSelection,
		current,
		deleteOrg,
		reinstateOrg,
		suspendOrg,
		updateOrg
	} from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	$: org = $activeOrg;
	$: if (org) {
		setMeta({
			title: 'Organisation settings',
			subtitle: `Identity and lifecycle for ${org.name}.`,
			crumbs: [{ label: org.name, href: '/app/org' }, { label: 'Settings' }]
		});
	}

	let name = $activeOrg?.name ?? '';
	let slug = $activeOrg?.slug ?? '';
	let contact = $activeOrg?.contactEmail ?? '';
	let lastOrgId = $activeOrg?.id ?? '';
	$: if ($activeOrg && $activeOrg.id !== lastOrgId) {
		lastOrgId = $activeOrg.id;
		name = $activeOrg.name;
		slug = $activeOrg.slug;
		contact = $activeOrg.contactEmail;
	}

	let suspending = false;
	let deleting = false;

	function save() {
		if (!org) {
			return;
		}
		updateOrg(org.id, { name, slug, contactEmail: contact });
		notify('success', 'Organisation settings saved.');
	}

	function confirmSuspend() {
		if (!org) {
			return;
		}
		suspendOrg(org.id);
		suspending = false;
		notify('error', 'Organisation suspended — all user tunnels are frozen.');
	}

	function confirmDelete() {
		if (!org) {
			return;
		}
		deleteOrg(org.id);
		clearSelection();
		deleting = false;
		notify('success', 'Organisation deleted.');
		void goto($current?.role === 'super_admin' ? '/app/admin/orgs' : '/sign-in');
	}
</script>

{#if org}
	<Panel title="Identity" subtitle="How the relay names {org.name}">
		<div class="form-grid">
			<div class="stack">
				<label for="org-name">Name</label>
				<input id="org-name" class="control" bind:value={name} />
			</div>
			<div class="stack">
				<label for="org-slug">Slug</label>
				<input id="org-slug" class="control mono" bind:value={slug} />
			</div>
			<div class="stack">
				<label for="org-contact">Contact email</label>
				<input id="org-contact" class="control" type="email" bind:value={contact} placeholder="ops@example.com" />
			</div>
		</div>
		<div class="actions-inline">
			<Keycap type="button" variant="primary" onclick={save}>Save changes</Keycap>
		</div>
	</Panel>

	<Panel title="Danger zone" subtitle="Lifecycle actions">
		<div class="danger">
			<div>
				<p class="danger__title">
					{org.status === 'suspended' ? 'Reinstate organisation' : 'Suspend organisation'}
				</p>
				<p class="muted">
					{org.status === 'suspended'
						? 'Restores user accounts so they can reopen their tunnels.'
						: 'Freezes every tunnel owned by every user in this organisation until reinstated.'}
				</p>
			</div>
			{#if org.status === 'suspended'}
				<Keycap
					type="button"
					variant="key"
					onclick={() => {
						reinstateOrg(org.id);
						notify('success', 'Organisation reinstated.');
					}}
				>
					<Icon name="check" size={15} /> Reinstate
				</Keycap>
			{:else}
				<Keycap type="button" variant="danger" onclick={() => (suspending = true)}>
					<Icon name="ban" size={15} /> Suspend
				</Keycap>
			{/if}
		</div>
		<div class="danger">
			<div>
				<p class="danger__title">Delete organisation</p>
				<p class="muted">Removes all users, machines and services. Cannot be undone.</p>
			</div>
			<Keycap type="button" variant="danger" onclick={() => (deleting = true)}>
				<Icon name="trash" size={15} /> Delete
			</Keycap>
		</div>
	</Panel>
{/if}

<Dialog bind:open={suspending} title="Suspend {org?.name}?" width={440}>
	<div class="alert">
		<Icon name="alert" size={18} />
		<p>Suspension is immediate and freezes every tunnel across the organisation.</p>
	</div>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (suspending = false)}>Cancel</Keycap>
		<Keycap type="button" variant="danger" onclick={confirmSuspend}>Suspend organisation</Keycap>
	</svelte:fragment>
</Dialog>

<ConfirmDeleteDialog
	bind:open={deleting}
	title="Delete {org?.name}?"
	expected={org?.name ?? ''}
	confirmLabel="Delete organisation"
	onConfirm={confirmDelete}
>
	<p>
		This permanently deletes <strong>{org?.name}</strong> and removes all users, machines and
		services under it.
	</p>
</ConfirmDeleteDialog>

<style lang="scss">
	.form-grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
		gap: 16px;
	}

	.actions-inline {
		margin-top: 16px;
	}

	.danger {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 16px;
		padding: 14px 0;
		border-bottom: 1px solid var(--tw-line-hair);
	}

	.danger:last-child {
		border-bottom: 0;
		padding-bottom: 0;
	}

	.danger__title {
		font-weight: 700;
		margin-bottom: 2px;
	}

	.alert {
		display: flex;
		gap: 12px;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.55;
	}

	.alert :global(svg) {
		color: var(--tw-danger);
		flex: none;
	}
</style>
