<script lang="ts">
	/**
	 * Virtualized HTTP request stream.
	 *
	 * - No owner or live reputation score columns on normal traffic; when
	 *   `showInfraction` is set (on the User Offense Page), displays the
	 *   triggered infraction classifier label for each sampled query.
	 * - Virtualizes rows (`ROW_HEIGHT = 40px`) inside a scroll viewport so large
	 *   transient captures stay fast without pagination.
	 * - Newly arrived rows expand smoothly from 0→40px at the top with a brief
	 *   phosphor highlight so existing rows glide down without jumping.
	 */
	import { bytes, clock, ms } from '#lib/mock/format';
	import { inspecting, machines } from '#lib/mock/store';
	import type { LogEntry } from '#lib/mock/types';
	import Icon from '#lib/ui/Icon.svelte';

	import { methodColor, statusColor } from './palette';

	export let entries: LogEntry[] = [];
	export let compact = false;
	export let showInfraction = false;
	export let emptyText = 'No requests captured in this view.';

	const ROW_HEIGHT = 40;
	const VIEWPORT_HEIGHT = 420;
	const OVERSCAN = 6;

	let scrollTop = 0;

	// Track which entry IDs were already present so only genuinely new arrivals
	// animate in at the top.
	let initialized = false;
	const seenIds = new Set<string>();
	let freshIds = new Set<string>();

	$: {
		if (!initialized && entries.length > 0) {
			for (const e of entries) {
				seenIds.add(e.id);
			}
			initialized = true;
		} else if (initialized) {
			const newlyAdded: string[] = [];
			for (const e of entries) {
				if (!seenIds.has(e.id)) {
					seenIds.add(e.id);
					newlyAdded.push(e.id);
				}
			}
			if (newlyAdded.length > 0) {
				freshIds = new Set([...freshIds, ...newlyAdded]);
				setTimeout(() => {
					const next = new Set(freshIds);
					for (const id of newlyAdded) {
						next.delete(id);
					}
					freshIds = next;
				}, 700);
			}
		}
	}

	$: serviceIndex = new Map(
		$machines.flatMap((m) => m.services.map((s) => [s.id, s] as const))
	);

	function hostOf(entry: LogEntry): string {
		return serviceIndex.get(entry.serviceId)?.hostname ?? '—';
	}

	$: totalHeight = entries.length * ROW_HEIGHT;
	$: startIdx = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN);
	$: endIdx = Math.min(
		entries.length,
		Math.ceil((scrollTop + VIEWPORT_HEIGHT) / ROW_HEIGHT) + OVERSCAN
	);
	$: visibleEntries = entries.slice(startIdx, endIdx);
	$: offsetTop = startIdx * ROW_HEIGHT;
	$: offsetBottom = Math.max(0, totalHeight - endIdx * ROW_HEIGHT);
</script>

<div class="feed">
	<div class="feed__head" class:with-infraction={showInfraction}>
		<span class="col-time">Time</span>
		<span class="col-method">Method</span>
		<span class="col-path">{compact ? 'Path · service' : 'Host · path'}</span>
		{#if showInfraction}
			<span class="col-infraction">Infraction</span>
		{/if}
		<span class="col-status">Status</span>
		<span class="col-size right">Size</span>
		<span class="col-dur right">Latency</span>
	</div>

	{#if entries.length > 0}
		<div
			class="feed__viewport"
			style="max-height: {VIEWPORT_HEIGHT}px"
			on:scroll={(e) => (scrollTop = e.currentTarget.scrollTop)}
		>
			<div style="padding-top: {offsetTop}px; padding-bottom: {offsetBottom}px">
				{#each visibleEntries as entry (entry.id)}
					<button
						class="entry"
						class:with-infraction={showInfraction}
						class:is-fresh={freshIds.has(entry.id)}
						type="button"
						on:click={() => inspecting.set(entry)}
					>
						<span class="col-time mono">{clock(entry.ts)}</span>
						<span class="col-method">
							<span class="method mono" style="color: {methodColor(entry.method)}">
								{entry.method}
							</span>
						</span>
						<span class="col-path">
							<span class="entry__path mono">{entry.path}</span>
							<span class="entry__host mono">{hostOf(entry)}</span>
						</span>
						{#if showInfraction}
							<span class="col-infraction">
								{#if entry.infraction}
									<span class="inf-badge mono">
										{#if entry.imagePreview}
											<span class="inf-badge__img">IMG</span>
										{/if}
										{entry.infraction}
									</span>
								{/if}
							</span>
						{/if}
						<span class="col-status">
							<span class="status mono" style="color: {statusColor(entry.status)}">
								<span class="status__dot" style="background: {statusColor(entry.status)}"></span>
								{entry.status}
							</span>
						</span>
						<span class="col-size mono right">{bytes(entry.bytesOut)}</span>
						<span class="col-dur mono right">{ms(entry.durationMs)}</span>
					</button>
				{/each}
			</div>
		</div>
	{:else}
		<p class="empty">{emptyText}</p>
	{/if}
</div>

<style lang="scss">
	.feed {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}

	.feed__head,
	.entry {
		display: grid;
		grid-template-columns: 82px 66px minmax(180px, 1fr) 74px 86px 82px;
		align-items: center;
		gap: 12px;
		padding: 0 14px;
	}

	.feed__head.with-infraction,
	.entry.with-infraction {
		grid-template-columns: 82px 62px minmax(160px, 1fr) minmax(190px, 240px) 68px 80px 76px;
	}

	.feed__head {
		min-height: 34px;
		background: var(--tw-well);
		border-bottom: 1.5px solid var(--tw-border);
		font-size: 11px;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.feed__viewport {
		overflow-y: auto;
		overscroll-behavior: contain;
	}

	.entry {
		width: 100%;
		height: 40px;
		border: 0;
		border-bottom: 1px solid var(--tw-line-hair);
		background: none;
		color: var(--tw-text);
		font: inherit;
		text-align: left;
		cursor: pointer;
		overflow: hidden;
	}

	.entry:hover {
		background: color-mix(in srgb, var(--tw-text) 6%, transparent);
	}

	// Top-down accordion expansion + phosphor trace highlight for newly arrived rows
	.entry.is-fresh {
		animation: log-row-reveal 620ms cubic-bezier(0.22, 1, 0.36, 1);
	}

	@keyframes log-row-reveal {
		0% {
			height: 0;
			opacity: 0;
			background: color-mix(in srgb, var(--tw-confirm) 34%, transparent);
		}
		35% {
			height: 40px;
			opacity: 1;
			background: color-mix(in srgb, var(--tw-confirm) 24%, transparent);
		}
		100% {
			height: 40px;
			opacity: 1;
			background: transparent;
		}
	}

	.col-time,
	.col-size,
	.col-dur {
		font-size: 12px;
		color: var(--tw-muted);
	}

	.right {
		text-align: right;
	}

	.method {
		font-size: 11px;
		font-weight: 700;
	}

	.col-path {
		display: flex;
		align-items: baseline;
		gap: 10px;
		min-width: 0;
	}

	.entry__path {
		font-size: 12px;
		font-weight: 600;
		color: var(--tw-text);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.entry__host {
		font-size: 11px;
		color: var(--tw-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.col-infraction {
		min-width: 0;
	}

	.inf-badge {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		max-width: 100%;
		padding: 2px 7px;
		border: 1px solid var(--tw-danger);
		background: color-mix(in srgb, var(--tw-danger) 12%, transparent);
		color: var(--tw-danger);
		font-size: 10px;
		font-weight: 700;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.inf-badge__img {
		padding: 0 4px;
		background: var(--tw-danger);
		color: var(--tw-well);
		font-size: 9px;
	}

	.status {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		font-size: 12px;
		font-weight: 700;
	}

	.status__dot {
		width: 7px;
		height: 7px;
		border-radius: 999px;
	}

	.empty {
		padding: 32px 14px;
		color: var(--tw-muted);
		font-size: 14px;
		text-align: center;
	}

	@media (prefers-reduced-motion: reduce) {
		.entry.is-fresh {
			animation: none;
		}
	}
</style>
