<script lang="ts">
	import Panel from '#lib/console/Panel.svelte';
	import Toggle from '#lib/console/Toggle.svelte';
	import { setMeta } from '#lib/console/meta';
	import { notify } from '#lib/account/notices';
	import { reputationColor } from '#lib/console/palette';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';

	setMeta({ title: 'Abuse thresholds', subtitle: 'How the ranker escalates across the fleet.', crumbs: [{ label: 'Thresholds' }] });

	let threshold = 50;
	let autoBan = true;
	let autoBanScore = 20;
	let retention = '30';
	let notifyOrgAdmins = true;

	let categories = [
		{ id: 'csam', label: 'Child sexual abuse material', on: true, locked: true },
		{ id: 'malware', label: 'Malware distribution', on: true, locked: false },
		{ id: 'phishing', label: 'Phishing & credential theft', on: true, locked: false },
		{ id: 'botnet', label: 'Botnet command & control', on: true, locked: false },
		{ id: 'scanner', label: 'Mass scanning & exploitation', on: true, locked: false },
		{ id: 'piracy', label: 'Large-scale copyright infringement', on: false, locked: false }
	];

	function save() {
		notify('success', 'Thresholds saved. Enforcement applies immediately fleet-wide.');
	}
</script>

<div class="layout">
	<Panel title="Review threshold" subtitle="Score at or below which a service is queued">
		<div class="slider">
			<input type="range" min="0" max="90" step="1" bind:value={threshold} aria-label="Review threshold" />
			<span class="slider__value mono" style="color: {reputationColor(threshold)}">{threshold}</span>
		</div>
		<p class="hint">
			Services scoring at or below <strong>{threshold}</strong> keep a sample of offending queries in
			the review queue for a human decision. A lower value means fewer, more confident flags.
		</p>
	</Panel>

	<Panel title="Automatic banning" subtitle="Enforcement without a human in the loop">
		<Toggle bind:checked={autoBan} label={autoBan ? 'Enabled' : 'Disabled'} />
		<div class="sub" class:disabled={!autoBan}>
			<div class="slider">
				<label for="autoban-score" class="sub__label">Auto-ban at or below</label>
				<input id="autoban-score" type="range" min="0" max="40" step="1" bind:value={autoBanScore} disabled={!autoBan} />
				<span class="slider__value mono" style="color: {reputationColor(autoBanScore)}">{autoBanScore}</span>
			</div>
			<Toggle bind:checked={notifyOrgAdmins} label="Notify the org admin" disabled={!autoBan} />
		</div>
	</Panel>

	<Panel title="Blocked categories" subtitle="The ranker's watchlist">
		<ul class="cats">
			{#each categories as cat (cat.id)}
				<li>
					<Toggle bind:checked={cat.on} label={cat.label} disabled={cat.locked} />
					{#if cat.locked}<span class="cats__locked mono"><Icon name="lock" size={12} /> always on</span>{/if}
				</li>
			{/each}
		</ul>
	</Panel>

	<Panel title="Sample retention" subtitle="How long flagged queries are kept">
		<select class="control" bind:value={retention}>
			<option value="7">7 days</option>
			<option value="30">30 days</option>
			<option value="90">90 days</option>
			<option value="365">1 year</option>
		</select>
		<p class="hint">
			Flagged samples are deleted after the retention window unless attached to an open case.
		</p>
	</Panel>
</div>

<div class="save-bar">
	<Keycap type="button" variant="primary" onclick={save}>
		<Icon name="check" size={15} /> Save thresholds
	</Keycap>
</div>

<style lang="scss">
	.layout {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(340px, 1fr));
		gap: 16px;
	}

	.slider {
		display: flex;
		align-items: center;
		gap: 16px;
	}

	.slider input[type='range'] {
		flex: 1;
		accent-color: var(--tw-accent);
	}

	.slider__value {
		font-size: 24px;
		font-weight: 700;
		min-width: 2ch;
	}

	.sub {
		display: flex;
		flex-direction: column;
		gap: 16px;
		margin-top: 16px;
		padding-top: 16px;
		border-top: 1px solid var(--tw-line-hair);
	}

	.sub.disabled {
		opacity: 0.5;
	}

	.sub__label {
		font-size: 14px;
		font-weight: 700;
		flex: none;
	}

	.cats {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 14px;
	}

	.cats li {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
	}

	.cats__locked {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		color: var(--tw-muted);
		font-size: 11px;
	}

	.save-bar {
		position: sticky;
		bottom: 0;
		display: flex;
		justify-content: flex-end;
		padding: 12px 0;
	}
</style>
