<script lang="ts">
	import Panel from '#lib/console/Panel.svelte';
	import { setMeta } from '#lib/console/meta';
	import { notify } from '#lib/account/notices';
	import { createOrg, current, selectOrg, updatePerson } from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	setMeta({
		title: 'Create an organisation',
		subtitle: 'Manage users, inspect traffic and moderate tunnels across your team.',
		crumbs: [{ label: 'Create organisation' }]
	});

	let name = '';
	let slug = '';
	let contact = '';

	$: slugHint = slug || name.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 20) || 'my-org';

	function create() {
		if (!$current || !name) {
			return;
		}
		const org = createOrg({ name, slug: slugHint, contactEmail: contact });
		updatePerson($current.person.id, { orgId: org.id, role: 'org_admin' });
		selectOrg(org.id);
		notify('success', `${name} created. You are now its organisation admin.`);
		void goto('/app/org');
	}
</script>

<div class="layout">
	<Panel title="Organisation details" subtitle="You can change all of this later">
		<div class="stack form">
			<div class="stack">
				<label for="new-org-name">Name</label>
				<input id="new-org-name" class="control" bind:value={name} placeholder="Acme Robotics" />
			</div>
			<div class="stack">
				<label for="new-org-slug">Slug</label>
				<input id="new-org-slug" class="control mono" bind:value={slug} placeholder={slugHint} />
				<p class="hint">Used in audit logs and support tooling: <code class="mono">{slugHint}</code>.</p>
			</div>
			<div class="stack">
				<label for="new-org-contact">Contact email</label>
				<input id="new-org-contact" class="control" type="email" bind:value={contact} placeholder="ops@acme.example" />
			</div>
		</div>
		<div class="actions-inline">
			<Keycap type="button" variant="primary" disabled={!name} onclick={create}>
				<Icon name="building" size={15} /> Create organisation
			</Keycap>
		</div>
	</Panel>

	<Panel title="What an organisation admin does" subtitle="Role separation">
		<ul class="perks">
			<li><Icon name="users" size={16} /> Create, edit and remove users in the organisation</li>
			<li><Icon name="activity" size={16} /> Inspect real-time bandwidth and statistics broken down by user</li>
			<li><Icon name="shield" size={16} /> Review suspicious HTTP query samples flagged by the ranker</li>
			<li><Icon name="ban" size={16} /> Suspend a user and freeze all of their tunnels immediately</li>
		</ul>
	</Panel>
</div>

<style lang="scss">
	.layout {
		display: grid;
		grid-template-columns: minmax(0, 1.4fr) minmax(0, 1fr);
		gap: 16px;
	}

	@media (max-width: 900px) {
		.layout {
			grid-template-columns: 1fr;
		}
	}

	.form {
		margin-top: 0;
	}

	.actions-inline {
		margin-top: 16px;
	}

	.perks {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 12px;
		color: var(--tw-muted);
		font-size: 14px;
	}

	.perks li {
		display: flex;
		align-items: center;
		gap: 10px;
	}

	.perks :global(svg) {
		color: var(--tw-accent);
	}
</style>
