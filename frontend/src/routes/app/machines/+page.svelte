<script lang="ts">
	/**
	 * The machines list: one page of the signed-in person's machines. Paging, the
	 * name search and the health filter are served by the relay — the browser only
	 * ever holds the page it is showing — and all three live in the address bar,
	 * so a filtered page is linkable and the back button works.
	 */
	import { onDestroy, onMount } from 'svelte';

	import { ensureConfig } from '#lib/account/config';
	import { notify } from '#lib/account/notices';
	import { bytes } from '#lib/app/format';
	import {
		disconnectMachine,
		listMachines,
		type Machine,
		type MachineQuery,
		renameMachine,
		revokeMachine
	} from '#lib/app/machines';
	import { timeAgo } from '#lib/app/time';
	import { setMeta } from '#lib/console/meta';
	import PairMachineDialog from '#lib/console/PairMachineDialog.svelte';
	import { searchQuery } from '#lib/console/search';
	import ConfirmDeleteDialog from '#lib/ui/ConfirmDeleteDialog.svelte';
	import Dialog from '#lib/ui/Dialog.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import HealthDot from '#lib/ui/HealthDot.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import Panel from '#lib/ui/Panel.svelte';
	import { afterNavigate, goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page as url } from '$app/state';

	type Health = NonNullable<MachineQuery['health']>;

	/**
	 * A deliberately large page: a person with an ordinary handful of machines
	 * never sees a second one, and the overview points here for the rest.
	 */
	const SIZE = 60;
	/** How long typing settles before the query is sent. */
	const SETTLE_MS = 150;

	let machines: Machine[] = [];
	let total = 0;
	let pageCount = 1;
	let loading = true;
	let error = '';

	/** The page the list is asking for. Written only by the pager and the filter. */
	let page = 1;
	/** The page the relay actually served: it clamps, so this can differ. */
	let currentPage = 1;

	let status: Health = 'all';

	let pairing = false;
	let renaming: Machine | null = null;
	let renameValue = '';
	let disconnecting: Machine | null = null;
	let revoking: Machine | null = null;
	let busy = false;

	let timer: ReturnType<typeof setTimeout> | undefined;
	/** Whether one load has landed: the very first one must not wait on a timer. */
	let loadedOnce = false;
	/** The query the rows on screen belong to, so only a *new* query debounces. */
	let loadedQuery = '';

	/** Only the two health values the collection accepts; anything else is `all`. */
	function readHealth(raw: string | null): Health {
		return raw === 'online' || raw === 'offline' ? raw : 'all';
	}

	function readPage(raw: string | null): number {
		return Math.max(1, Number(raw) || 1);
	}

	// Seed from the URL before the first fetch, so a link opens where it says.
	const initial = url.url.searchParams;
	page = readPage(initial.get('page'));
	status = readHealth(initial.get('health'));
	searchQuery.set(initial.get('q') ?? '');

	setMeta({
		title: 'Machines',
		subtitle: 'Every machine paired to your account.',
		crumbs: [{ label: 'Machines' }]
	});

	// Back and forward land on the list with the state the URL carries.
	afterNavigate((navigation) => {
		const params = navigation.to?.url.searchParams;
		if (!params) {
			return;
		}
		const wanted = readPage(params.get('page'));
		if (wanted !== page) {
			page = wanted;
		}
		const health = readHealth(params.get('health'));
		if (health !== status) {
			status = health;
		}
		const query = params.get('q') ?? '';
		if (query !== $searchQuery) {
			searchQuery.set(query);
		}
	});

	// Any change to the query, the filter or the page refetches that page. Only
	// *typing* settles for a beat: the first load, the health filter and the pager
	// are single deliberate acts, and parking them on a keystroke timer is pure
	// added latency on a request that already answers in tens of milliseconds.
	$: schedule($searchQuery, status, page);

	function schedule(query: string, health: Health, wanted: number) {
		clearTimeout(timer);
		if (!loadedOnce || query === loadedQuery) {
			void load(query, health, wanted);
			return;
		}
		timer = setTimeout(() => void load(query, health, wanted), SETTLE_MS);
	}

	onDestroy(() => clearTimeout(timer));

	onMount(() => {
		void ensureConfig().catch(() => {});
	});

	async function load(query: string, health: Health, wanted: number) {
		loading = true;
		error = '';
		loadedOnce = true;
		loadedQuery = query;
		const res = await listMachines({ page: wanted, perPage: SIZE, q: query, health });
		loading = false;
		if (!res.ok || !res.data) {
			error = res.error ?? 'We could not load your machines. Please try again.';
			machines = [];
			total = 0;
			pageCount = 1;
			return;
		}
		machines = res.data.machines;
		total = res.data.total;
		pageCount = res.data.page_count;
		// The relay clamps the page it returns; the pager follows that, while the
		// request cursor is left alone so this never re-triggers the fetch.
		currentPage = res.data.page;
		syncUrl();
	}

	/** Re-read the page the list is on, after an action changed it. */
	function reload() {
		void load($searchQuery, status, currentPage);
	}

	/** Writes the list's state into the address bar, without re-running the page. */
	function syncUrl() {
		const parts: string[] = [];
		if ($searchQuery) {
			parts.push(`q=${encodeURIComponent($searchQuery)}`);
		}
		if (status !== 'all') {
			parts.push(`health=${status}`);
		}
		if (currentPage > 1) {
			parts.push(`page=${currentPage}`);
		}
		const suffix = parts.length ? `?${parts.join('&')}` : '';
		if (`${url.url.pathname}${url.url.search}` !== `/app/machines${suffix}`) {
			// `resolve()` is typed against route ids and cannot carry a query
			// string, so the list route is resolved and the query appended.
			// eslint-disable-next-line svelte/no-navigation-without-resolve -- the path is the resolved list route
			void goto(resolve('/app/machines') + suffix, { replace: true, shallow: true });
		}
	}

	$: from = total === 0 ? 0 : (currentPage - 1) * SIZE + 1;
	$: to = Math.min(currentPage * SIZE, total);

	function startRename(machine: Machine) {
		renaming = machine;
		renameValue = machine.name;
	}

	async function confirmRename() {
		if (!renaming || !/^[a-z0-9]{1,15}$/.test(renameValue)) {
			return;
		}
		const target = renaming;
		busy = true;
		const res = await renameMachine(target.id, renameValue);
		busy = false;
		if (!res.ok || !res.data) {
			notify('error', res.error ?? 'We could not rename that machine. Please try again.');
			return;
		}
		renaming = null;
		notify('success', `Renamed to ${res.data.name}. Its hostnames follow immediately.`);
		reload();
	}

	async function confirmDisconnect() {
		if (!disconnecting) {
			return;
		}
		const target = disconnecting;
		busy = true;
		const res = await disconnectMachine(target.id);
		busy = false;
		disconnecting = null;
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
		reload();
	}

	async function confirmRevoke() {
		if (!revoking) {
			return;
		}
		const target = revoking;
		busy = true;
		const res = await revokeMachine(target.id);
		busy = false;
		revoking = null;
		if (!res.ok) {
			notify('error', res.error ?? 'We could not revoke that machine. Please try again.');
			return;
		}
		notify('success', `Revoked ${target.name}. Its tunnel dropped and its hostnames stop serving.`);
		reload();
	}
</script>

{#if error}
	<p class="notice-error" role="alert">{error}</p>
{/if}

<Panel flush title="Machines" subtitle="{total} paired · click a row to open a machine">
	<svelte:fragment slot="actions">
		<Keycap type="button" size="sm" variant="primary" onclick={() => (pairing = true)}>
			<Icon name="plus" size={15} /> Pair a machine
		</Keycap>
	</svelte:fragment>

	<div class="toolbar">
		<select
			class="control control--sm"
			bind:value={status}
			on:change={() => (page = 1)}
			aria-label="Filter by health"
		>
			<option value="all">Any health</option>
			<option value="online">Online</option>
			<option value="offline">Offline</option>
		</select>
		<span class="toolbar__spacer"></span>
	</div>

	{#if loading}
		<p class="state" aria-live="polite">Loading your machines…</p>
	{:else if machines.length}
		<div class="table-wrap">
			<table class="table">
				<colgroup>
					<col style="width: 24%" />
					<col style="width: 14%" />
					<col style="width: 14%" />
					<col style="width: 24%" />
					<col style="width: 24%" />
				</colgroup>
				<thead>
					<tr>
						<th>Machine</th>
						<th>Health</th>
						<th>Last seen</th>
						<th class="right">Bandwidth · 30d</th>
						<th></th>
					</tr>
				</thead>
				<tbody>
					{#each machines as machine (machine.id)}
						<tr
							class="row-link"
							role="link"
							tabindex="0"
							on:click={() =>
								void goto(resolve('/app/machines/[machine]', { machine: `${machine.id}` }))}
							on:keydown={(event) => {
								if (event.key === 'Enter' || event.key === ' ') {
									event.preventDefault();
									void goto(resolve('/app/machines/[machine]', { machine: `${machine.id}` }));
								}
							}}
						>
							<td><span class="cell-name">{machine.name}</span></td>
							<td><HealthDot online={machine.online} /></td>
							<td class="mono nowrap">{timeAgo(machine.last_seen_at)}</td>
							<td class="mono nowrap right">
								{bytes(machine.usage_30d.bytes_in + machine.usage_30d.bytes_out)}
							</td>
							<td class="right" on:click|stopPropagation>
								<div class="row-actions">
									{#if machine.online}
										<Keycap
											type="button"
											size="sm"
											variant="ghost"
											title="Disconnect {machine.name}"
											ariaLabel="Disconnect {machine.name}"
											onclick={() => (disconnecting = machine)}
										>
											<Icon name="power" size={14} /> Disconnect
										</Keycap>
									{/if}
									<Keycap
										type="button"
										size="sm"
										variant="ghost"
										title="Rename {machine.name}"
										ariaLabel="Rename {machine.name}"
										onclick={() => startRename(machine)}
									>
										<Icon name="rename" size={14} />
									</Keycap>
									<Keycap
										type="button"
										size="sm"
										variant="ghost"
										title="Revoke {machine.name}"
										ariaLabel="Revoke {machine.name}"
										onclick={() => (revoking = machine)}
									>
										<Icon name="ban" size={14} />
									</Keycap>
								</div>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{:else}
		<EmptyState
			icon="machine"
			title={$searchQuery || status !== 'all' ? 'No machines match' : 'No machines yet'}
			text={$searchQuery || status !== 'all'
				? 'Adjust the filter, or clear the search, to find a machine.'
				: 'Pair a machine with `weave pair` to expose a service through the relay.'}
		/>
	{/if}

	<svelte:fragment slot="footer">
		<Pagination
			bare
			page={currentPage}
			{pageCount}
			{total}
			{from}
			{to}
			unit="machines"
			onPage={(next: number) => (page = next)}
		/>
	</svelte:fragment>
</Panel>

<PairMachineDialog bind:open={pairing} />

<Dialog
	open={renaming !== null}
	title="Rename machine"
	width={460}
	onClose={() => (renaming = null)}
>
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
		<Keycap type="button" variant="key" onclick={() => (renaming = null)}>Cancel</Keycap>
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
	open={disconnecting !== null}
	title="Disconnect {disconnecting?.name ?? 'machine'}?"
	width={460}
	onClose={() => (disconnecting = null)}
>
	<p class="muted">
		Immediately drops <strong>{disconnecting?.name}</strong>'s tunnel. Its key is kept, so it does
		not reconnect on its own — run <code class="mono">weave start</code> on the machine to bring it back.
		Its hostnames keep their names.
	</p>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (disconnecting = null)}>
			No, keep it connected
		</Keycap>
		<Keycap type="button" variant="danger" disabled={busy} onclick={confirmDisconnect}>
			<Icon name="power" size={14} /> Disconnect machine
		</Keycap>
	</svelte:fragment>
</Dialog>

<ConfirmDeleteDialog
	open={revoking !== null}
	title="Revoke {revoking?.name ?? 'machine'}?"
	expected={revoking?.name ?? ''}
	confirmLabel="Revoke machine"
	cancelLabel="Keep machine"
	onClose={() => (revoking = null)}
	onConfirm={confirmRevoke}
>
	<p>
		Revokes <strong>{revoking?.name}</strong>'s key immediately. Its live tunnel drops and its
		hostnames stop serving. This cannot be undone from here — pair the machine again to bring it
		back.
	</p>
</ConfirmDeleteDialog>

<style lang="scss">
	.notice-error {
		margin-bottom: 12px;
	}

	.state {
		padding: 24px 16px;
		color: var(--tw-muted);
	}

	.toolbar {
		padding-top: 12px;
	}

	.table-wrap {
		overflow-x: auto;
	}

	.row-link {
		cursor: pointer;
	}

	.row-link:hover {
		background: color-mix(in srgb, var(--tw-accent) 8%, transparent);
	}

	.cell-name {
		display: block;
		font-weight: 700;
		color: var(--tw-text);
		overflow-wrap: anywhere;
	}

	.form {
		margin-top: 0;
	}
</style>
