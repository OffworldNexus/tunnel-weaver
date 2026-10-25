<script lang="ts">
	/**
	 * The machines list: one page of the signed-in person's machines. Paging, the
	 * name search and the health filter live in the address bar — the route's
	 * `load` reads them back and the URL is the single source of truth — so a
	 * filtered page is linkable and the back button works.
	 *
	 * Nothing here waits: a keystroke reaches the address bar at once, and the
	 * route's `load` answers in milliseconds — well within a frame — so there is
	 * nothing to settle. While a response is in flight the panel keeps the rows
	 * it already has, which are the previous page's real ones, instead of
	 * blanking itself for a frame.
	 */
	import { untrack } from 'svelte';

	import { notify } from '#lib/account/notices';
	import { bytes } from '#lib/app/format';
	import { streamJson } from '#lib/app/live';
	import {
		disconnectMachine,
		type Machine,
		type MachineHealth,
		type MachinePage,
		machinesUrl,
		readHealth,
		readPage,
		renameMachine,
		revokeMachine
	} from '#lib/app/machines';
	import { timeAgo } from '#lib/app/time';
	import { climb } from '#lib/app/upgrade';
	import { setMeta } from '#lib/console/meta.svelte';
	import PairMachineDialog from '#lib/console/PairMachineDialog.svelte';
	import { search } from '#lib/console/search.svelte';
	import ConfirmDeleteDialog from '#lib/ui/ConfirmDeleteDialog.svelte';
	import Dialog from '#lib/ui/Dialog.svelte';
	import EmptyState from '#lib/ui/EmptyState.svelte';
	import HealthDot from '#lib/ui/HealthDot.svelte';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import Pagination from '#lib/ui/Pagination.svelte';
	import Panel from '#lib/ui/Panel.svelte';
	import { afterNavigate, goto, invalidate } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';

	import type { PageProps } from './$types';

	/** The list state the address bar carries. */
	interface ListState {
		q: string;
		health: MachineHealth;
		page: number;
	}

	let { data }: PageProps = $props();

	let pairing = $state(false);
	let renaming = $state<Machine | null>(null);
	let renameValue = $state('');
	let disconnecting = $state<Machine | null>(null);
	let revoking = $state<Machine | null>(null);
	let busy = $state(false);

	/**
	 * The latest pushed page, or `null` until the first frame. The loader's copy
	 * renders first; a pushed snapshot replaces it and every later change arrives
	 * on the same stream, without a reload.
	 */
	let pushed = $state<MachinePage | null>(null);

	/**
	 * The rows the template renders. The pushed snapshot wins once it has arrived;
	 * until then the loader's first paint is shown, so there is never an empty
	 * frame. `null` also resets on every new query below, so a page change never
	 * keeps a previous page's rows on screen.
	 */
	const view = $derived(
		pushed
			? {
					machines: pushed.machines,
					total: pushed.total,
					page: pushed.page,
					pageCount: pushed.page_count,
					perPage: pushed.per_page
				}
			: {
					machines: data.machines,
					total: data.total,
					page: data.page,
					pageCount: data.pageCount,
					perPage: data.perPage
				}
	);

	// One stream per query: a page, search or filter change resubscribes, and the
	// old stream is closed by the effect's cleanup. The relay re-sends the whole
	// page on every relevant change, so the UI follows machines coming online,
	// going offline, pairing and being revoked.
	$effect(() => {
		const url = machinesUrl({
			page: data.page,
			perPage: data.perPage,
			q: data.q,
			health: data.health
		});
		pushed = null;
		return streamJson<MachinePage>(url, (page) => {
			pushed = page;
		});
	});

	setMeta({
		title: 'Machines',
		subtitle: 'Every machine paired to your account.',
		crumbs: [{ label: 'Machines' }]
	});

	/** The list's state as the address bar carries it. */
	function address(): ListState {
		return {
			q: page.url.searchParams.get('q') ?? '',
			health: readHealth(page.url.searchParams.get('health')),
			page: readPage(page.url.searchParams.get('page'))
		};
	}

	/** The query string for a list state, in a stable order. */
	function query(state: ListState): string {
		const parts: string[] = [];
		if (state.q) {
			parts.push(`q=${encodeURIComponent(state.q)}`);
		}
		if (state.health !== 'all') {
			parts.push(`health=${state.health}`);
		}
		if (state.page > 1) {
			parts.push(`page=${state.page}`);
		}
		return parts.length ? `?${parts.join('&')}` : '';
	}

	/** Writes a list state into the address bar, without reloading the page. */
	function write(state: ListState) {
		const suffix = query(state);
		if (`${page.url.pathname}${page.url.search}` === `/app/machines${suffix}`) {
			return;
		}
		// `resolve()` is typed against route ids and cannot carry a query
		// string, so the list route is resolved and the query appended.
		// eslint-disable-next-line svelte/no-navigation-without-resolve -- the path is the resolved list route
		void goto(resolve('/app/machines') + suffix, {
			replace: true,
			// SvelteKit 3 folds the old `keepFocus`/`noScroll` pair into this:
			// leave the caret in the search field and the scroll position alone.
			reset: false
		});
	}

	// Adopt the URL's query into the shared top-bar state whenever the loader
	// brings a new one, so a deep link — or the back button — opens the field on
	// what the address says. It reads only `data.q`, so typing never retriggers it.
	$effect(() => {
		search.q = data.q;
	});

	// Back and forward land on the list with the state the URL carries; settling
	// the parts the relay clamps — a page past the end, an unknown health — keeps
	// the address bar matching the rows on screen.
	afterNavigate(() => {
		if (page.url.pathname !== '/app/machines') {
			return;
		}
		write({ q: data.q, health: data.health, page: data.page });
	});

	// A keystroke reaches the address bar at once. The write reads the URL
	// untracked, and only the store is tracked, so landing on the list — back,
	// forward, a deep link — changes the address without scheduling a write of
	// its own that would fight it.
	$effect(() => {
		const q = search.q;
		untrack(() => write({ ...address(), q }));
	});

	const from = $derived(view.total === 0 ? 0 : (view.page - 1) * view.perPage + 1);
	const to = $derived(Math.min(view.page * view.perPage, view.total));

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
		const res = await renameMachine(target.id, renameValue, climb);
		busy = false;
		if (res.refused) {
			return;
		}
		if (!res.ok || !res.data) {
			notify('error', res.error ?? 'We could not rename that machine. Please try again.');
			return;
		}
		renaming = null;
		notify('success', `Renamed to ${res.data.name}. Its hostnames follow immediately.`);
		await invalidate('app:machines');
	}

	async function confirmDisconnect() {
		if (!disconnecting) {
			return;
		}
		const target = disconnecting;
		busy = true;
		const res = await disconnectMachine(target.id, climb);
		busy = false;
		if (res.refused) {
			return;
		}
		disconnecting = null;
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
		if (!revoking) {
			return;
		}
		const target = revoking;
		busy = true;
		const res = await revokeMachine(target.id, climb);
		busy = false;
		if (res.refused) {
			return;
		}
		revoking = null;
		if (!res.ok) {
			notify('error', res.error ?? 'We could not revoke that machine. Please try again.');
			return;
		}
		notify('success', `Revoked ${target.name}. Its tunnel dropped and its hostnames stop serving.`);
		await invalidate('app:machines');
	}
</script>

<Panel flush title="Machines" subtitle="{view.total} paired · click a row to open a machine">
	{#snippet actions()}
		<Keycap type="button" size="sm" variant="primary" onclick={() => (pairing = true)}>
			<Icon name="plus" size={15} /> Pair a machine
		</Keycap>
	{/snippet}

	<div class="toolbar">
		<select
			class="control control--sm"
			value={data.health}
			onchange={(event) => {
				write({
					...address(),
					q: search.q,
					health: readHealth(event.currentTarget.value),
					page: 1
				});
			}}
			aria-label="Filter by health"
		>
			<option value="all">Any health</option>
			<option value="online">Online</option>
			<option value="offline">Offline</option>
		</select>
		<span class="toolbar__spacer"></span>
	</div>

	{#if view.machines.length}
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
					{#each view.machines as machine (machine.id)}
						<tr
							class="row-link"
							role="link"
							tabindex="0"
							onclick={() =>
								void goto(resolve('/app/machines/[machine]', { machine: `${machine.id}` }))}
							onkeydown={(event) => {
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
							<td class="right" onclick={(event) => event.stopPropagation()}>
								<div class="row-actions">
									{#if machine.online}
										<Keycap
											type="button"
											size="sm"
											variant="ghost"
											title="Kick {machine.name}"
											ariaLabel="Kick {machine.name}"
											onclick={() => (disconnecting = machine)}
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
			title={search.q || data.health !== 'all' ? 'No machines match' : 'No machines yet'}
			text={search.q || data.health !== 'all'
				? 'Adjust the filter, or clear the search, to find a machine.'
				: 'Pair a machine with `weave pair` to expose a service through the relay.'}
		/>
	{/if}

	{#snippet footer()}
		<Pagination
			bare
			page={view.page}
			pageCount={view.pageCount}
			total={view.total}
			{from}
			{to}
			unit="machines"
			onPage={(next: number) => {
				write({ ...address(), q: search.q, page: next });
			}}
		/>
	{/snippet}
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
		<Keycap type="button" variant="key" onclick={() => (renaming = null)}>Cancel</Keycap>
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
	open={disconnecting !== null}
	title="Kick {disconnecting?.name ?? 'machine'}?"
	width={460}
	onClose={() => (disconnecting = null)}
>
	<p class="muted">
		Immediately drops <strong>{disconnecting?.name}</strong>'s tunnel. Its key is kept, so it does
		not reconnect on its own — run <code class="mono">weave start</code> on the machine to bring it back.
		Its hostnames keep their names.
	</p>
	{#snippet footer()}
		<Keycap type="button" variant="key" onclick={() => (disconnecting = null)}>
			No, keep it connected
		</Keycap>
		<Keycap type="button" variant="danger" disabled={busy} onclick={confirmDisconnect}>
			<Icon name="power" size={14} /> Kick machine
		</Keycap>
	{/snippet}
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
