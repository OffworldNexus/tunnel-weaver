<script lang="ts">
	/**
	 * One machine: its identity and key fingerprint, and the public hostnames it
	 * serves. Everything shown is read from the relay; the actions rename,
	 * kick or revoke it.
	 *
	 * The machine arrives from the route's `load`, so it is always present — an
	 * id that is not this account's machine is an error, not an empty page. An
	 * action that changes the machine invalidates the shared `app:machines` key;
	 * revoking removes it, so that one leaves for the list.
	 */
	import { notify } from '#lib/account/notices';
	import { fingerprint } from '#lib/app/fingerprint';
	import { bytes } from '#lib/app/format';
	import { disconnectMachine, renameMachine, revokeMachine } from '#lib/app/machines';
	import { date, timeAgo } from '#lib/app/time';
	import { setMeta } from '#lib/console/meta';
	import Badge from '#lib/ui/Badge.svelte';
	import ConfirmDeleteDialog from '#lib/ui/ConfirmDeleteDialog.svelte';
	import Dialog from '#lib/ui/Dialog.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import HealthDot from '#lib/ui/HealthDot.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Panel from '#lib/ui/Panel.svelte';
	import { goto, invalidate } from '$app/navigation';
	import { resolve } from '$app/paths';

	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const machine = $derived(data.machine);

	let renaming = $state(false);
	let renameValue = $state('');
	let disconnecting = $state(false);
	let revoking = $state(false);
	let busy = $state(false);

	// The shell renders the page head; it follows whatever machine is loaded.
	$effect(() => {
		setMeta({
			title: machine.name,
			subtitle: `Paired ${date(machine.paired_at)} · last seen ${timeAgo(machine.last_seen_at)}`,
			crumbs: [{ label: 'Machines', href: '/app/machines' }, { label: machine.name }]
		});
	});

	function startRename() {
		renaming = true;
		renameValue = machine.name;
	}

	async function confirmRename() {
		if (!/^[a-z0-9]{1,15}$/.test(renameValue)) {
			return;
		}
		busy = true;
		const res = await renameMachine(machine.id, renameValue);
		busy = false;
		if (!res.ok || !res.data) {
			notify('error', res.error ?? 'We could not rename that machine. Please try again.');
			return;
		}
		renaming = false;
		notify('success', `Renamed to ${res.data.name}. Its hostnames follow immediately.`);
		await invalidate('app:machines');
	}

	async function confirmDisconnect() {
		const target = machine;
		busy = true;
		const res = await disconnectMachine(target.id);
		busy = false;
		disconnecting = false;
		if (!res.ok || !res.data) {
			notify('error', res.error ?? 'We could not kick that machine. Please try again.');
			return;
		}
		notify(
			'success',
			res.data.disconnected
				? `Kicked ${target.name}. Run \`weave start\` on it to bring it back.`
				: `${target.name} was already offline.`
		);
		await invalidate('app:machines');
	}

	async function confirmRevoke() {
		const target = machine;
		busy = true;
		const res = await revokeMachine(target.id);
		busy = false;
		revoking = false;
		if (!res.ok) {
			notify('error', res.error ?? 'We could not revoke that machine. Please try again.');
			return;
		}
		notify('success', `Revoked ${target.name}. Its tunnel dropped and its hostnames stop serving.`);
		await goto(resolve('/app/machines'));
	}
</script>

<div class="stack-page">
	<Panel title="Machine">
		{#snippet actions()}
			{#if machine.online}
				<Keycap
					type="button"
					size="sm"
					variant="ghost"
					ariaLabel="Kick {machine.name}"
					onclick={() => (disconnecting = true)}
				>
					<Icon name="power" size={14} /> Kick
				</Keycap>
			{/if}
			<Keycap
				type="button"
				size="sm"
				variant="key"
				ariaLabel="Rename {machine.name}"
				onclick={startRename}
			>
				<Icon name="rename" size={14} /> Rename
			</Keycap>
			<Keycap
				type="button"
				size="sm"
				variant="danger"
				ariaLabel="Revoke {machine.name}"
				onclick={() => (revoking = true)}
			>
				<Icon name="ban" size={14} /> Revoke
			</Keycap>
		{/snippet}

		<dl class="identity">
			<div>
				<dt>Status</dt>
				<dd><HealthDot online={machine.online} /></dd>
			</div>
			<div>
				<dt>Key fingerprint</dt>
				<dd class="mono fp">{fingerprint(machine.fingerprint)}</dd>
			</div>
		</dl>
	</Panel>

	<Panel flush title="Services" subtitle="The public hostnames this machine serves">
		{#if machine.services.length}
			<div class="table-wrap">
				<table class="table">
					<colgroup>
						<col style="width: 20%" />
						<col style="width: 14%" />
						<col style="width: 40%" />
						<col style="width: 26%" />
					</colgroup>
					<thead>
						<tr>
							<th>Service</th>
							<th>Status</th>
							<th>Public URL</th>
							<th class="right">Bandwidth · 30d</th>
						</tr>
					</thead>
					<tbody>
						{#each machine.services as svc (svc.name)}
							<tr>
								<td class="mono">{svc.name}</td>
								<td>
									<Badge dot variant={svc.active ? 'ok' : 'muted'}>
										{svc.active ? 'live' : 'idle'}
									</Badge>
								</td>
								<td>
									{#if svc.hostnames.length}
										<div class="hosts">
											{#each svc.hostnames as host (host)}
												<a
													class="host"
													href="https://{host}"
													target="_blank"
													rel="noopener noreferrer"
												>
													{host}
													<Icon name="external" size={13} />
												</a>
											{/each}
										</div>
									{:else}
										<span class="muted">—</span>
									{/if}
								</td>
								<td class="mono nowrap right">
									{bytes(svc.usage_30d.bytes_in + svc.usage_30d.bytes_out)}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{:else}
			<EmptyState
				icon="network"
				title="No services yet"
				text="This machine has not declared any service through the relay."
			/>
		{/if}
	</Panel>
</div>

<Dialog open={renaming} title="Rename machine" width={460} onClose={() => (renaming = false)}>
	<div class="stack form">
		<label for="mach-rename">New name</label>
		<input
			id="mach-rename"
			class="control mono"
			bind:value={renameValue}
			oninput={() =>
				(renameValue = renameValue
					.toLowerCase()
					.replace(/[^a-z0-9]/g, '')
					.slice(0, 15))}
		/>
		<p class="muted">
			Lowercase letters and digits only, up to 15 characters. The machine's hostnames follow the new
			name immediately.
		</p>
	</div>
	{#snippet footer()}
		<Keycap type="button" variant="key" onclick={() => (renaming = false)}>Cancel</Keycap>
		<Keycap
			type="button"
			variant="primary"
			disabled={busy || !/^[a-z0-9]{1,15}$/.test(renameValue)}
			onclick={confirmRename}
		>
			Rename
		</Keycap>
	{/snippet}
</Dialog>

<Dialog
	open={disconnecting}
	title="Kick {machine.name}?"
	width={460}
	onClose={() => (disconnecting = false)}
>
	<p class="muted">
		Immediately drops <strong>{machine.name}</strong>'s tunnel. Its key is kept, so it does not
		reconnect on its own — run <code class="mono">weave start</code> on the machine to bring it back.
		Its hostnames keep their names.
	</p>
	{#snippet footer()}
		<Keycap type="button" variant="key" onclick={() => (disconnecting = false)}>
			No, keep it connected
		</Keycap>
		<Keycap type="button" variant="danger" disabled={busy} onclick={confirmDisconnect}>
			<Icon name="power" size={14} /> Kick machine
		</Keycap>
	{/snippet}
</Dialog>

<ConfirmDeleteDialog
	open={revoking}
	title="Revoke {machine.name}?"
	expected={machine.name}
	confirmLabel="Revoke machine"
	cancelLabel="Keep machine"
	onClose={() => (revoking = false)}
	onConfirm={confirmRevoke}
>
	<p>
		Revokes <strong>{machine.name}</strong>'s key immediately. Its live tunnel drops and its
		hostnames stop serving. This cannot be undone from here — pair the machine again to bring it
		back.
	</p>
</ConfirmDeleteDialog>

<style lang="scss">
	.stack-page {
		display: grid;
		gap: 20px;
	}

	.identity {
		display: grid;
		margin: 0;
		padding: 0;
	}

	.identity div {
		display: flex;
		justify-content: space-between;
		gap: 16px;
		padding: 12px 0;
		border-bottom: 1px solid var(--tw-line-hair);
	}

	.identity div:last-child {
		border-bottom: 0;
	}

	.identity dt {
		color: var(--tw-muted);
		font-size: 13px;
		font-weight: 700;
	}

	.identity dd {
		margin: 0;
		text-align: right;
		overflow-wrap: anywhere;
	}

	.fp {
		font-size: 12px;
	}

	.table-wrap {
		overflow-x: auto;
	}

	.hosts {
		display: flex;
		flex-wrap: wrap;
		gap: 4px 14px;
	}

	.host {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		font-family: var(--tw-mono);
		font-size: 13px;
	}

	.form {
		margin-top: 0;
	}
</style>
