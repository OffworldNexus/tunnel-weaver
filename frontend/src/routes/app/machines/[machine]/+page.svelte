<script lang="ts">
	/**
	 * One machine: its identity and key fingerprint, and the public hostnames it
	 * serves. Everything shown is read from the relay; the actions rename,
	 * disconnect or revoke it.
	 */
	import { onMount } from 'svelte';

	import { notify } from '#lib/account/notices';
	import { fingerprint } from '#lib/app/fingerprint';
	import { bytes } from '#lib/app/format';
	import {
		disconnectMachine,
		getMachine,
		type Machine,
		renameMachine,
		revokeMachine
	} from '#lib/app/machines';
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
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';

	let machine: Machine | null = null;
	let loading = true;
	let error = '';

	let renaming = false;
	let renameValue = '';
	let disconnecting = false;
	let revoking = false;
	let busy = false;

	onMount(() => {
		const id = Number(page.params.machine);
		if (Number.isFinite(id) && id > 0) {
			void load(id);
			return;
		}
		loading = false;
		error = 'That machine does not belong to your account.';
	});

	// The shell renders the page head; it follows whatever machine is loaded.
	$: setMeta({
		title: machine?.name ?? 'Machine',
		subtitle: machine
			? `Paired ${date(machine.paired_at)} · last seen ${timeAgo(machine.last_seen_at)}`
			: '',
		crumbs: [{ label: 'Machines', href: '/app/machines' }, { label: machine?.name ?? '…' }]
	});

	async function load(machineId: number) {
		loading = true;
		error = '';
		const res = await getMachine(machineId);
		loading = false;
		if (!res.ok || !res.data) {
			machine = null;
			error = res.error ?? 'We could not load that machine. Please try again.';
			return;
		}
		machine = res.data;
	}

	function startRename() {
		if (!machine) {
			return;
		}
		renaming = true;
		renameValue = machine.name;
	}

	async function confirmRename() {
		if (!machine || !/^[a-z0-9]{1,15}$/.test(renameValue)) {
			return;
		}
		const id = machine.id;
		busy = true;
		const res = await renameMachine(id, renameValue);
		busy = false;
		if (!res.ok || !res.data) {
			notify('error', res.error ?? 'We could not rename that machine. Please try again.');
			return;
		}
		renaming = false;
		notify('success', `Renamed to ${res.data.name}. Its hostnames follow immediately.`);
		await load(id);
	}

	async function confirmDisconnect() {
		if (!machine) {
			return;
		}
		const target = machine;
		busy = true;
		const res = await disconnectMachine(target.id);
		busy = false;
		disconnecting = false;
		if (!res.ok || !res.data) {
			notify('error', res.error ?? 'We could not disconnect that machine. Please try again.');
			return;
		}
		notify(
			'success',
			res.data.disconnected
				? `Disconnected ${target.name}. Run \`weave start\` on it to reconnect.`
				: `${target.name} was already offline.`
		);
		await load(target.id);
	}

	async function confirmRevoke() {
		if (!machine) {
			return;
		}
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

{#if loading}
	<p class="state" aria-live="polite">Loading machine…</p>
{:else if !machine}
	<p class="notice-error" role="alert">
		{error || 'That machine does not belong to your account.'}
	</p>
{:else}
	<div class="stack-page">
		<Panel title="Machine">
			<svelte:fragment slot="actions">
				{#if machine.online}
					<Keycap
						type="button"
						size="sm"
						variant="ghost"
						ariaLabel="Disconnect {machine.name}"
						onclick={() => (disconnecting = true)}
					>
						<Icon name="power" size={14} /> Disconnect
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
			</svelte:fragment>

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
{/if}

<Dialog open={renaming} title="Rename machine" width={460} onClose={() => (renaming = false)}>
	<div class="stack form">
		<label for="mach-rename">New name</label>
		<input
			id="mach-rename"
			class="control mono"
			bind:value={renameValue}
			on:input={() =>
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
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (renaming = false)}>Cancel</Keycap>
		<Keycap
			type="button"
			variant="primary"
			disabled={busy || !/^[a-z0-9]{1,15}$/.test(renameValue)}
			onclick={confirmRename}
		>
			Rename
		</Keycap>
	</svelte:fragment>
</Dialog>

<Dialog
	open={disconnecting}
	title="Disconnect {machine?.name ?? 'machine'}?"
	width={460}
	onClose={() => (disconnecting = false)}
>
	<p class="muted">
		Immediately drops <strong>{machine?.name}</strong>'s tunnel. Its key is kept, so it does not
		reconnect on its own — run <code class="mono">weave start</code> on the machine to bring it back.
		Its hostnames keep their names.
	</p>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (disconnecting = false)}>
			No, keep it connected
		</Keycap>
		<Keycap type="button" variant="danger" disabled={busy} onclick={confirmDisconnect}>
			<Icon name="power" size={14} /> Disconnect machine
		</Keycap>
	</svelte:fragment>
</Dialog>

<ConfirmDeleteDialog
	open={revoking}
	title="Revoke {machine?.name ?? 'machine'}?"
	expected={machine?.name ?? ''}
	confirmLabel="Revoke machine"
	cancelLabel="Keep machine"
	onClose={() => (revoking = false)}
	onConfirm={confirmRevoke}
>
	<p>
		Revokes <strong>{machine?.name}</strong>'s key immediately. Its live tunnel drops and its
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

	.state {
		padding: 24px 0;
		color: var(--tw-muted);
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
