<script lang="ts">
	/**
	 * The machine detail page:
	 * 1. Machine identity, fingerprint & lifecycle actions (Kick machine if
	 *    connected, Rename, Verify, Unpair).
	 * 2. Open services and their public URLs (read-only status; services cannot
	 *    be toggled individually from the web UI).
	 * 3. Live bandwidth & on-the-wire speed graph, scoped by a multi-select over
	 *    the machine's services.
	 * 4. Transient live HTTP query capture (off by default, virtualized list
	 *    without pagination, click any row to open the Svaul inspection drawer).
	 */
	import Badge from '#lib/console/Badge.svelte';
	import BandwidthChart from '#lib/console/BandwidthChart.svelte';
	import ConfirmDeleteDialog from '#lib/console/ConfirmDeleteDialog.svelte';
	import Dialog from '#lib/console/Dialog.svelte';
	import EmptyState from '#lib/console/EmptyState.svelte';
	import HealthDot from '#lib/console/HealthDot.svelte';
	import LogStream from '#lib/console/LogStream.svelte';
	import Pagination from '#lib/console/Pagination.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import Reputation from '#lib/console/Reputation.svelte';
	import ServiceMultiSelect from '#lib/console/ServiceMultiSelect.svelte';
	import Spark from '#lib/console/Spark.svelte';
	import Toggle from '#lib/console/Toggle.svelte';
	import { setMeta } from '#lib/console/meta';
	import { paginate } from '#lib/console/paginate';
	import { projectedBytes, serviceSeries } from '#lib/console/series';
	import { notify } from '#lib/account/notices';
	import { bytes, date, timeAgo } from '#lib/mock/format';
	import {
		capturingLogs,
		clearCapturedLogs,
		current,
		healthOf,
		kickMachine,
		logs,
		machines,
		orgOfPerson,
		personOfMachine,
		renameMachine,
		selectPerson,
		startLogCapture,
		stopLogCapture,
		unpairMachine,
		verifyMachine
	} from '#lib/mock/store';
	import type { Machine } from '#lib/mock/types';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';

	export let id: string;

	let renaming = false;
	let renameValue = '';
	let kicking = false;
	let unpairing = false;

	// Multi-select service scope (empty array = all services on this machine)
	let selectedServiceIds: string[] = [];

	// Live log filters
	let logQuery = '';
	let logMethod = 'all';
	let logStatus = 'all';

	let servicePage = 1;

	$: machine = $machines.find((m) => m.id === id);
	$: person = machine ? personOfMachine(machine) : undefined;
	$: org = person ? orgOfPerson(person) : undefined;
	$: isOwner = person?.id === $current?.person.id;
	$: canModerate = $current?.role === 'org_admin' || $current?.role === 'super_admin';
	$: health = machine ? healthOf(machine) : 'offline';
	$: openCount = machine?.services.filter((s) => s.tunnel === 'open').length ?? 0;

	$: if (person && !isOwner) {
		selectPerson(person.id);
	}

	$: if (machine) {
		setMeta({
			title: machine.name,
			subtitle: `${machine.hostname} · ${machine.os}`,
			crumbs: [
				...(org && !isOwner ? [{ label: org.name, href: '/app/org' }] : []),
				...(person && !isOwner
					? [{ label: person.name, href: `/app/people/${person.id}` }]
					: []),
				{ label: 'Machines', href: '/app/machines' },
				{ label: machine.name }
			]
		});
	}

	$: servicePaged = paginate(machine?.services ?? [], servicePage, 8);

	// Filtered services for the usage graph and live logs
	$: activeServices = machine
		? selectedServiceIds.length === 0
			? machine.services
			: machine.services.filter((s) => selectedServiceIds.includes(s.id))
		: [];

	$: activeServiceSet = new Set(activeServices.map((s) => s.id));

	// Synthetic Machine wrapper so BandwidthChart renders the selected service subset
	$: scopedMachines = (
		machine
			? [
					{
						...machine,
						services: activeServices,
						series: serviceSeries(activeServices)
					} satisfies Machine
				]
			: []
	);

	// Transient live HTTP logs for this machine
	$: filteredLogs = $logs.filter((entry) => {
		if (entry.machineId !== id) {
			return false;
		}
		const okSvc = activeServiceSet.has(entry.serviceId);
		const okQ = logQuery === '' || entry.path.toLowerCase().includes(logQuery.toLowerCase());
		const okMethod = logMethod === 'all' || entry.method === logMethod;
		const klass = `${Math.floor(entry.status / 100)}xx`;
		const okStatus = logStatus === 'all' || klass === logStatus;
		return okSvc && okQ && okMethod && okStatus;
	});

	function startRename() {
		if (!machine) {
			return;
		}
		renameValue = machine.name;
		renaming = true;
	}

	function confirmRename() {
		if (!machine || !/^[a-z0-9]{1,15}$/.test(renameValue)) {
			return;
		}
		renameMachine(machine.id, renameValue);
		notify('success', `Renamed to ${renameValue}. Hostnames follow immediately.`);
		renaming = false;
	}

	function confirmKick() {
		if (!machine) {
			return;
		}
		kickMachine(machine.id);
		kicking = false;
		notify(
			'success',
			`Disconnected ${machine.name}. To reconnect, run weave start on the machine.`
		);
	}

	function confirmUnpair() {
		if (!machine) {
			return;
		}
		unpairMachine(machine.id);
		unpairing = false;
		notify('success', 'Machine unpaired. Its tunnel is dropped and its hostnames stop serving.');
		void goto(isOwner ? '/app/machines' : `/app/people/${person?.id ?? ''}`);
	}

	function handleCaptureToggle(next: boolean) {
		if (next) {
			startLogCapture(id);
		} else {
			stopLogCapture();
		}
	}
</script>

{#if !machine}
	<Panel><EmptyState icon="machine" title="Machine not found" text="It may have been unpaired." /></Panel>
{:else}
	<Panel flush cut={18}>
		<div class="hero">
			<div class="hero__badges">
				<HealthDot {health} />
				<Badge variant={machine.verified ? 'ok' : 'warn'}>
					{machine.verified ? 'verified' : 'unverified'}
				</Badge>
				<Badge variant="neutral">weave {machine.agentVersion}</Badge>
				<span class="muted hero__meta">
					Paired {date(machine.pairedAt)} · last seen {timeAgo(machine.lastSeenAt)}
				</span>
			</div>
			<div class="hero__actions">
				{#if machine.online}
					<Keycap type="button" size="sm" variant="key" onclick={() => (kicking = true)}>
						<Icon name="power" size={15} /> Kick machine
					</Keycap>
				{/if}
				<Keycap type="button" size="sm" variant="key" onclick={startRename}>
					<Icon name="rename" size={15} /> Rename
				</Keycap>
				{#if !machine.verified}
					<Keycap
						type="button"
						size="sm"
						variant="key"
						onclick={() => {
							verifyMachine(machine.id);
							notify('success', 'Fingerprint marked as verified.');
						}}
					>
						<Icon name="check" size={15} /> Verify
					</Keycap>
				{/if}
				<Keycap type="button" size="sm" variant="danger" onclick={() => (unpairing = true)}>
					<Icon name="ban" size={15} /> Unpair
				</Keycap>
			</div>
		</div>

		<div class="fp-row">
			<span class="fp-row__label">Key fingerprint</span>
			<code class="fp-row__val mono">{machine.fingerprint}</code>
		</div>
	</Panel>

	<Panel
		flush
		title="Open services & URLs"
		subtitle="{openCount} of {machine.services.length} tunnels open · registered by weave on this machine"
	>
		<div class="table-wrap">
			<table class="table">
				<thead>
					<tr>
						<th>Service · target</th>
						<th>Public URL</th>
						<th>External · 1h</th>
						<th class="right">Bandwidth · 30d</th>
						{#if canModerate}<th>Reputation</th>{/if}
						<th>Status</th>
					</tr>
				</thead>
				<tbody>
					{#each servicePaged.items as service (service.id)}
						<tr>
							<td>
								<span class="cell-name mono">{service.name}</span>
								<span class="cell-sub mono">→ {service.target}</span>
							</td>
							<td class="nowrap">
								<a
									class="url-link mono"
									href="https://{service.hostname}"
									target="_blank"
									rel="noreferrer"
								>
									https://{service.hostname}
									<Icon name="external" size={12} />
								</a>
							</td>
							<td>
								<span class="bw-cell">
									<span class="spark">
										<Spark
											data={service.series.slice(-60).map((p) => p.bytesIn + p.bytesOut)}
											color="var(--tw-c1)"
											height={24}
										/>
									</span>
									<span class="bw-cell__val mono">
										{bytes(service.bytesIn + service.bytesOut)}
									</span>
								</span>
							</td>
							<td class="right mono">
								{bytes(
									projectedBytes(
										[{ ...machine, services: [service], series: service.series }],
										'both'
									)
								)}
							</td>
							{#if canModerate}
								<td><Reputation score={service.reputation} compact /></td>
							{/if}
							<td>
								<Badge
									dot
									variant={service.tunnel === 'open'
										? 'ok'
										: service.tunnel === 'suspended'
											? 'danger'
											: 'muted'}
								>
									{service.tunnel}
								</Badge>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<Pagination
			page={servicePaged.page}
			pageCount={servicePaged.pageCount}
			total={servicePaged.total}
			from={servicePaged.from}
			to={servicePaged.to}
			unit="services"
			onPage={(p) => (servicePage = p)}
		/>
	</Panel>

	<div class="svc-filter-bar">
		<ServiceMultiSelect
			services={machine.services}
			bind:selectedIds={selectedServiceIds}
		/>
	</div>

	<BandwidthChart
		machines={scopedMachines}
		title="Live bandwidth & on-the-wire usage"
		subtitle={selectedServiceIds.length === 0
			? `All services on ${machine.name}`
			: `${activeServices.map((s) => s.name).join(', ')}`}
		height={250}
	/>

	<Panel
		flush
		title="Live HTTP queries"
		subtitle={$capturingLogs
			? `Capturing live transient stream (${filteredLogs.length} queries in buffer) · click any row to inspect`
			: 'Transient capture is off — requests are only streamed to your browser while capture is active'}
	>
		<svelte:fragment slot="actions">
			{#if $capturingLogs || filteredLogs.length > 0}
				<Keycap
					type="button"
					size="sm"
					variant="ghost"
					onclick={clearCapturedLogs}
				>
					Clear buffer
				</Keycap>
			{/if}
			<Toggle
				checked={$capturingLogs}
				compact
				label={$capturingLogs ? 'Capture ON' : 'Capture OFF'}
				onChange={handleCaptureToggle}
			/>
		</svelte:fragment>

		{#if !$capturingLogs && filteredLogs.length === 0}
			<div class="capture-standby">
				<div class="capture-standby__well">
					<span class="capture-standby__icon"><Icon name="terminal" size={26} /></span>
					<h3 class="capture-standby__title">Transient HTTP query capture</h3>
					<p class="capture-standby__copy">
						Tunnel Weaver does not persist traffic logs at rest. Start a live capture session to
						stream a transient copy of HTTP requests passing through
						<strong class="mono">{machine.name}</strong> directly into this browser tab.
					</p>
					<div class="capture-standby__cta">
						<Keycap
							type="button"
							variant="primary"
							onclick={() => startLogCapture(id)}
						>
							<Icon name="play" size={15} /> Start capturing logs
						</Keycap>
					</div>
				</div>
			</div>
		{:else}
			<div class="toolbar">
				<label class="searchbox">
					<Icon name="search" size={16} />
					<input
						class="searchbox__input"
						type="search"
						placeholder="Filter by path (e.g. /api/)"
						bind:value={logQuery}
					/>
				</label>
				<ServiceMultiSelect
					services={machine.services}
					bind:selectedIds={selectedServiceIds}
				/>
				<select class="control control--sm" bind:value={logMethod} aria-label="HTTP method">
					<option value="all">Any method</option>
					{#each ['GET', 'POST', 'PUT', 'DELETE', 'HEAD'] as m (m)}
						<option value={m}>{m}</option>
					{/each}
				</select>
				<select class="control control--sm" bind:value={logStatus} aria-label="Status class">
					<option value="all">Any status</option>
					<option value="2xx">2xx</option>
					<option value="3xx">3xx</option>
					<option value="4xx">4xx</option>
					<option value="5xx">5xx</option>
				</select>
				<span class="toolbar__spacer"></span>
				<span class="muted mono capture-count">{filteredLogs.length} captured</span>
			</div>

			<LogStream
				entries={filteredLogs}
				compact
				emptyText="Waiting for matching HTTP queries…"
			/>
		{/if}
	</Panel>
{/if}

<Dialog bind:open={kicking} title="Kick {machine?.name ?? 'machine'}?" width={460}>
	<div class="modal-copy">
		<p>
			Immediately disconnects <strong>{machine?.name}</strong> and drops all {openCount} open
			service tunnel{openCount === 1 ? '' : 's'}. This action cannot be undone from the web UI — to
			reconnect, the user must run <code class="mono">weave start</code> on the machine itself.
		</p>
	</div>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (kicking = false)}>No, keep connected</Keycap>
		<Keycap type="button" variant="danger" onclick={confirmKick}>
			<Icon name="power" size={14} /> Yes, kick machine
		</Keycap>
	</svelte:fragment>
</Dialog>

<Dialog bind:open={renaming} title="Rename machine" width={460}>
	<p class="muted">
		The machine's hostnames and certificates follow the new name immediately; the old name stops
		being served.
	</p>
	<div class="stack rename">
		<label for="machine-name">New name</label>
		<input
			id="machine-name"
			class="control mono"
			bind:value={renameValue}
			on:input={() => (renameValue = renameValue.toLowerCase().replace(/[^a-z0-9]/g, '').slice(0, 15))}
		/>
		<p class="hint">
			Lowercase letters and digits, up to 15 characters. Final hostnames look like
			<code class="mono">{person?.slug ?? 'person'}-{renameValue || 'machine'}-service.wvr.run</code>.
		</p>
	</div>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (renaming = false)}>Cancel</Keycap>
		<Keycap
			type="button"
			variant="primary"
			disabled={!/^[a-z0-9]{1,15}$/.test(renameValue)}
			onclick={confirmRename}
		>
			Rename
		</Keycap>
	</svelte:fragment>
</Dialog>

<ConfirmDeleteDialog
	bind:open={unpairing}
	title="Unpair {machine?.name ?? 'machine'}?"
	expected={machine?.name ?? ''}
	confirmLabel="Unpair machine"
	cancelLabel="Keep machine"
	onConfirm={confirmUnpair}
>
	<p>
		This deletes <strong>{machine?.name}</strong>'s key. Its live tunnel drops immediately, every
		hostname stops serving, and <code class="mono">weave</code> on the machine will report the
		revocation. To reconnect, someone must run <code class="mono">weave pair</code> again.
	</p>
</ConfirmDeleteDialog>

<style lang="scss">
	.hero {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 14px;
		padding: 14px 18px;
		border-bottom: 1.5px solid var(--tw-border);
	}

	.hero__badges {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 10px;
	}

	.hero__meta {
		font-size: 13px;
	}

	.hero__actions {
		display: flex;
		flex-wrap: wrap;
		gap: 8px;
	}

	.fp-row {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 12px;
		padding: 12px 18px;
	}

	.fp-row__label {
		font-size: 11px;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.fp-row__val {
		font-size: 13px;
	}

	.table-wrap {
		overflow-x: auto;
	}

	.cell-name {
		display: block;
		font-weight: 700;
		color: var(--tw-text);
	}

	.cell-sub {
		display: block;
		font-size: 11px;
		color: var(--tw-muted);
		white-space: nowrap;
	}

	.url-link {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		font-size: 12px;
		color: var(--tw-accent);
	}

	.bw-cell {
		display: inline-flex;
		align-items: center;
		gap: 10px;
	}

	.spark {
		display: block;
		width: 96px;
		height: 24px;
	}

	.bw-cell__val {
		font-size: 12px;
		color: var(--tw-muted);
		min-width: 58px;
		text-align: right;
	}

	.svc-filter-bar {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: flex-end;
		gap: 10px;
	}

	.capture-standby {
		display: grid;
		place-items: center;
		min-height: 340px;
		padding: 36px 20px;
		background:
			repeating-linear-gradient(
				0deg,
				color-mix(in srgb, var(--tw-text) 2.5%, transparent) 0 1px,
				transparent 1px 4px
			),
			var(--tw-well);
	}

	.capture-standby__well {
		max-width: 480px;
		display: flex;
		flex-direction: column;
		align-items: center;
		text-align: center;
		gap: 10px;
	}

	.capture-standby__icon {
		display: grid;
		place-items: center;
		width: 54px;
		height: 54px;
		border: 1.5px dashed var(--tw-border);
		color: var(--tw-accent);
	}

	.capture-standby__title {
		font-family: var(--tw-heading);
		font-size: 18px;
		font-weight: 700;
	}

	.capture-standby__copy {
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.55;
	}

	.capture-standby__copy strong {
		color: var(--tw-text);
	}

	.capture-standby__cta {
		margin-top: 8px;
	}

	.searchbox {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		height: 32px;
		padding: 0 10px;
		border: 1.5px solid var(--tw-border);
		border-radius: var(--tw-radius);
		background: var(--tw-well);
		color: var(--tw-muted);
	}

	.searchbox__input {
		border: 0;
		background: none;
		color: var(--tw-text);
		font: 400 13px/1 var(--tw-sans);
		outline: none;
		width: 220px;
	}

	.capture-count {
		font-size: 12px;
	}

	.rename {
		margin-top: 14px;
	}

	.modal-copy {
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.55;
	}

	.modal-copy strong {
		color: var(--tw-text);
	}
</style>
