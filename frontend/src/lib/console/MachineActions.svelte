<script lang="ts">
	/**
	 * The per-machine actions, shared by the overview's short list and the full
	 * list: kick, rename and revoke, each behind the confirmation it deserves.
	 *
	 * The component owns its dialogs and its in-flight state. Once a machine
	 * actually changed it invalidates the shared `app:machines` key, so every
	 * page that depends on it — the overview's stats and list, the full list,
	 * the machine's own page — reloads from the relay. No callback plumbing, and
	 * no page left showing a stale row.
	 *
	 * A kick drops the live tunnel and keeps the key, so the machine stays down
	 * until `weave start` runs on it again; revoking drops the key for good.
	 */
	import { notify } from '#lib/account/notices';
	import { disconnectMachine, type Machine, renameMachine, revokeMachine } from '#lib/app/machines';
	import ConfirmDeleteDialog from '#lib/ui/ConfirmDeleteDialog.svelte';
	import Dialog from '#lib/ui/Dialog.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { invalidate } from '$app/navigation';

	let { machine }: { machine: Machine } = $props();

	let renaming = $state(false);
	let renameValue = $state('');
	let kicking = $state(false);
	let revoking = $state(false);
	let busy = $state(false);

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

	async function confirmKick() {
		busy = true;
		const res = await disconnectMachine(machine.id);
		busy = false;
		kicking = false;
		if (!res.ok || !res.data) {
			notify('error', res.error ?? 'We could not kick that machine. Please try again.');
			return;
		}
		notify(
			'success',
			res.data.disconnected
				? `Kicked ${machine.name}. Run \`weave start\` on it to bring it back.`
				: `${machine.name} was already offline.`
		);
		await invalidate('app:machines');
	}

	async function confirmRevoke() {
		busy = true;
		const res = await revokeMachine(machine.id);
		busy = false;
		revoking = false;
		if (!res.ok) {
			notify('error', res.error ?? 'We could not revoke that machine. Please try again.');
			return;
		}
		notify(
			'success',
			`Revoked ${machine.name}. Its tunnel dropped and its hostnames stop serving.`
		);
		await invalidate('app:machines');
	}
</script>

<div class="row-actions">
	{#if machine.online}
		<Keycap
			type="button"
			size="sm"
			variant="ghost"
			title="Kick {machine.name}"
			ariaLabel="Kick {machine.name}"
			onclick={() => (kicking = true)}
		>
			<Icon name="power" size={14} /> Kick
		</Keycap>
	{/if}
	<Keycap
		type="button"
		size="sm"
		variant="ghost"
		title="Rename {machine.name}"
		ariaLabel="Rename {machine.name}"
		onclick={startRename}
	>
		<Icon name="rename" size={14} />
	</Keycap>
	<Keycap
		type="button"
		size="sm"
		variant="ghost"
		title="Revoke {machine.name}"
		ariaLabel="Revoke {machine.name}"
		onclick={() => (revoking = true)}
	>
		<Icon name="ban" size={14} />
	</Keycap>
</div>

<Dialog open={renaming} title="Rename machine" width={460} onClose={() => (renaming = false)}>
	<div class="stack form">
		<label for="machine-rename">New name</label>
		<input
			id="machine-rename"
			class="control mono"
			type="text"
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

<Dialog open={kicking} title="Kick {machine.name}?" width={460} onClose={() => (kicking = false)}>
	<p class="muted">
		Immediately drops <strong>{machine.name}</strong>'s tunnel. Its key is kept, so it does not
		reconnect on its own — run <code class="mono">weave start</code> on the machine to bring it back.
		Its hostnames keep their names.
	</p>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (kicking = false)}>
			No, leave it connected
		</Keycap>
		<Keycap type="button" variant="danger" disabled={busy} onclick={confirmKick}>
			<Icon name="power" size={14} /> Kick machine
		</Keycap>
	</svelte:fragment>
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
