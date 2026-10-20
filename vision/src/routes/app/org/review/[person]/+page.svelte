<script lang="ts">
	/**
	 * User Offense Page (`/app/org/review/[person]`):
	 * - Decision metrics: distinct visitor fingerprints hitting this user's tunnels
	 *   and the quantity of each detected infraction category.
	 * - Sampled image infractions (blurred by default, each labelled with its
	 *   infraction category) + full sampled HTTP query list (`LogStream`) with
	 *   click-to-inspect drawer.
	 * - Confirmation-backed actions: Clear of bad behaviour (deletes suspicion &
	 *   recomputes reputation) or Ban user (records annotation, freezes tunnels,
	 *   purges raw samples).
	 */
	import Badge from '#lib/console/Badge.svelte';
	import BanDialog from '#lib/console/BanDialog.svelte';
	import Bars from '#lib/console/Bars.svelte';
	import Dialog from '#lib/console/Dialog.svelte';
	import EmptyState from '#lib/console/EmptyState.svelte';
	import LogStream from '#lib/console/LogStream.svelte';
	import Panel from '#lib/console/Panel.svelte';
	import Reputation from '#lib/console/Reputation.svelte';
	import Toggle from '#lib/console/Toggle.svelte';
	import { setMeta } from '#lib/console/meta';
	import { notify } from '#lib/account/notices';
	import { bytes, clock } from '#lib/mock/format';
	import {
		banPersonWithNote,
		clearPersonOffenses,
		inspecting,
		machines,
		orgById,
		people,
		review,
		selectPerson
	} from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';

	let clearing = false;
	let banning = false;
	let blurImages = true;

	$: personId = page.params.person ?? '';
	$: person = $people.find((p) => p.id === personId);
	$: org = person ? orgById(person.orgId) : undefined;
	$: if (person) {
		selectPerson(person.id);
		setMeta({
			title: `${person.name} · Offense report`,
			subtitle: `${person.email} · ${org?.name ?? ''}`,
			crumbs: [
				...(org ? [{ label: org.name, href: '/app/org' }] : []),
				{ label: 'Review queue', href: '/app/org/review' },
				{ label: person.name }
			]
		});
	}

	$: userItems = $review.filter((r) => r.personId === personId && r.verdict === 'pending');
	$: fingerprints = userItems.reduce((a, r) => a + r.distinctFingerprints, 0);

	$: infractionBars = (() => {
		const map = new Map<string, { count: number; severity: string }>();
		for (const item of userItems) {
			for (const inf of item.infractions) {
				const prev = map.get(inf.category);
				map.set(inf.category, {
					count: (prev?.count ?? 0) + inf.count,
					severity: inf.severity
				});
			}
		}
		return [...map.entries()]
			.map(([label, v]) => ({
				label,
				value: v.count,
				color: v.severity === 'critical' ? 'var(--tw-danger)' : 'var(--tw-c1)',
				hint: v.severity
			}))
			.sort((a, b) => b.value - a.value);
	})();

	$: totalInfractions = infractionBars.reduce((a, b) => a + b.value, 0);

	$: sampledQueries = userItems
		.flatMap((r) => r.sample)
		.sort((a, b) => b.ts - a.ts);

	$: imageSamples = sampledQueries.filter((q) => q.imagePreview !== '');

	$: flaggedServices = userItems.map((item) => {
		const m = $machines.find((mach) => mach.id === item.machineId);
		const s = m?.services.find((svc) => svc.id === item.serviceId);
		return { item, machine: m, service: s };
	});

	function confirmClear() {
		if (!person) {
			return;
		}
		clearPersonOffenses(person.id);
		clearing = false;
		notify(
			'success',
			`${person.name} cleared of bad behaviour. Suspicion records deleted and reputation recomputed.`
		);
		void goto('/app/org/review');
	}

	function confirmBan(note: string) {
		if (!person) {
			return;
		}
		banPersonWithNote(person.id, note);
		banning = false;
		notify(
			'error',
			`${person.name} banned — tunnels frozen, annotation recorded, raw samples purged.`
		);
		void goto(`/app/people/${person.id}`);
	}
</script>

{#if !person}
	<Panel><EmptyState icon="users" title="User not found" /></Panel>
{:else if userItems.length === 0}
	<Panel>
		<EmptyState
			icon="shield"
			title="No pending offenses for {person.name}"
			text="This user has no active suspicion samples in the review queue."
		>
			<Keycap variant="key" size="sm" href="/app/people/{person.id}">Open user page</Keycap>
		</EmptyState>
	</Panel>
{:else}
	<div class="decision-bar">
		<div class="decision-bar__meta">
			<Badge variant="danger" dot>{userItems.length} flagged service{userItems.length === 1 ? '' : 's'}</Badge>
			<Reputation score={person.reputation} showLabel />
			<span class="muted">
				on {flaggedServices.map((x) => x.service?.hostname ?? x.item.serviceId).join(', ')}
			</span>
		</div>
		<div class="decision-bar__actions">
			<Keycap type="button" size="sm" variant="key" onclick={() => (clearing = true)}>
				<Icon name="check" size={14} /> Clear of bad behaviour
			</Keycap>
			<Keycap type="button" size="sm" variant="danger" onclick={() => (banning = true)}>
				<Icon name="ban" size={14} /> Ban user
			</Keycap>
		</div>
	</div>

	<div class="grid grid--wide">
		<Panel title="Visitor fingerprint telemetry" subtitle="Traffic distribution across flagged tunnels">
			<dl class="fp-stats">
				<div>
					<dt>Distinct visitor fingerprints</dt>
					<dd class="mono">{fingerprints}</dd>
					<span class="fp-stats__sub">Unique TLS + header fingerprints</span>
				</div>
				<div>
					<dt>Total infractions detected</dt>
					<dd class="mono danger-text">{totalInfractions}</dd>
					<span class="fp-stats__sub">Across {userItems.length} service{userItems.length === 1 ? '' : 's'}</span>
				</div>
				<div>
					<dt>Automated scraper traffic</dt>
					<dd class="mono">68%</dd>
					<span class="fp-stats__sub">Non-browser / bulk downloader UAs</span>
				</div>
				<div>
					<dt>Autonomous systems</dt>
					<dd class="mono">{Math.max(4, Math.round(fingerprints / 9))} ASNs</dd>
					<span class="fp-stats__sub">Spread across 5 edge regions</span>
				</div>
			</dl>
		</Panel>

		<Panel title="Infractions by category" subtitle="Quantity detected by the abuse ranker">
			<Bars items={infractionBars} />
		</Panel>
	</div>

	{#if imageSamples.length > 0}
		<Panel
			title="Sampled image infractions"
			subtitle="{imageSamples.length} visual sample{imageSamples.length === 1 ? '' : 's'} captured · each labelled with its triggered classifier"
		>
			<svelte:fragment slot="actions">
				<Toggle bind:checked={blurImages} compact label={blurImages ? 'Safety blur ON' : 'Revealed'} />
			</svelte:fragment>

			<div class="evidence-grid">
				{#each imageSamples as img (img.id)}
					<div class="evidence-card">
						<div class="evidence-card__head">
							<span class="infraction-pill mono">
								<Icon name="flag" size={12} /> {img.infraction}
							</span>
						</div>
						<button
							type="button"
							class="evidence-card__frame"
							class:is-blurred={blurImages}
							on:click={() => inspecting.set(img)}
							title="Click to inspect full HTTP request & response"
						>
							<img src={img.imagePreview} alt={img.infraction} />
							{#if blurImages}
								<span class="evidence-card__shield mono">BLURRED · CLICK TO INSPECT</span>
							{/if}
						</button>
						<div class="evidence-card__foot mono">
							<span class="ellipsis" title={img.path}>{img.method} {img.path}</span>
							<span>{clock(img.ts)} · {bytes(img.bytesOut)}</span>
						</div>
					</div>
				{/each}
			</div>
		</Panel>
	{/if}

	<Panel
		flush
		title="Sampled offending HTTP queries"
		subtitle="{sampledQueries.length} captured requests · click any row to inspect headers, payload and response"
	>
		<LogStream entries={sampledQueries} compact showInfraction />
	</Panel>
{/if}

<Dialog bind:open={clearing} title="Clear {person?.name} of bad behaviour?" width={460}>
	<div class="modal-copy">
		<p>
			Clearing <strong>{person?.name}</strong> deletes all {userItems.length} suspicion record{userItems.length === 1 ? '' : 's'}
			and sampled infractions, removes the flag from their services, and recomputes both their
			reputation score and <strong>{org?.name ?? 'the organisation'}</strong>'s moderation score.
		</p>
	</div>
	<svelte:fragment slot="footer">
		<Keycap type="button" variant="key" onclick={() => (clearing = false)}>Cancel</Keycap>
		<Keycap type="button" variant="primary" onclick={confirmClear}>
			<Icon name="check" size={14} /> Confirm & clear user
		</Keycap>
	</svelte:fragment>
</Dialog>

<BanDialog
	bind:open={banning}
	title="Ban {person?.name}?"
	confirmLabel="Ban user & freeze tunnels"
	defaultNote={person
		? `Confirmed ${infractionBars[0]?.label ?? 'abuse infractions'} across ${fingerprints} visitor fingerprints on ${person.slug}'s tunnels; raw samples purged on ban.`
		: ''}
	onConfirm={confirmBan}
>
	<p>
		Immediately suspends <strong>{person?.name}</strong> and freezes all of their tunnels. Your
		annotation and the non-content proof tally ({fingerprints} fingerprints, {totalInfractions}
		infractions) are retained on the user page while raw offending samples are purged.
	</p>
</BanDialog>

<style lang="scss">
	.decision-bar {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		padding-bottom: 14px;
		border-bottom: 1.5px solid var(--tw-border);
		font-size: 13px;
	}

	.decision-bar__meta {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 12px;
	}

	.decision-bar__actions {
		display: flex;
		flex-wrap: wrap;
		gap: 10px;
	}

	.fp-stats {
		display: grid;
		grid-template-columns: repeat(2, 1fr);
		gap: 18px 22px;
		margin: 0;
	}

	.fp-stats dt {
		font-size: 11px;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.fp-stats dd {
		margin: 5px 0 2px;
		font-size: 26px;
		font-weight: 700;
		line-height: 1;
	}

	.danger-text {
		color: var(--tw-danger);
	}

	.fp-stats__sub {
		font-size: 12px;
		color: var(--tw-muted);
	}

	.evidence-grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
		gap: 14px;
	}

	.evidence-card {
		display: flex;
		flex-direction: column;
		border: 1.5px solid var(--tw-border);
		background: var(--tw-raised);
	}

	.evidence-card__head {
		padding: 8px 10px;
		border-bottom: 1px solid var(--tw-line-hair);
		background: color-mix(in srgb, var(--tw-danger) 12%, var(--tw-well));
	}

	.infraction-pill {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		color: var(--tw-danger);
		font-size: 11px;
		font-weight: 700;
	}

	.evidence-card__frame {
		position: relative;
		padding: 0;
		border: 0;
		background: #0b0604;
		cursor: pointer;
		overflow: hidden;
		aspect-ratio: 420 / 220;
	}

	.evidence-card__frame img {
		display: block;
		width: 100%;
		height: 100%;
		object-fit: cover;
		transition: filter 160ms ease;
	}

	.evidence-card__frame.is-blurred img {
		filter: blur(12px) contrast(0.85);
	}

	.evidence-card__shield {
		position: absolute;
		inset: auto 10px 10px 10px;
		padding: 4px 8px;
		background: rgb(11 6 4 / 0.88);
		border: 1px solid var(--tw-border);
		color: var(--tw-text);
		font-size: 10px;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-align: center;
	}

	.evidence-card__foot {
		display: flex;
		justify-content: space-between;
		gap: 8px;
		padding: 8px 10px;
		border-top: 1px solid var(--tw-line-hair);
		font-size: 11px;
		color: var(--tw-muted);
	}

	.ellipsis {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
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
