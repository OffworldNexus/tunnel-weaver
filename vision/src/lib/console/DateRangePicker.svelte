<script lang="ts">
	/**
	 * Range selector for the bandwidth graph, combining the videotex preset rail
	 * (defaulting to the real-time floating 3h window) with `@ark-ui/svelte`'s
	 * `DatePicker` (`selectionMode="range"`) for arbitrary calendar date ranges.
	 */
	import { DatePicker, parseDate, type DatePickerValueChangeDetails } from '@ark-ui/svelte/date-picker';
	import { Portal } from '@ark-ui/svelte/portal';

	import Icon from '#lib/ui/Icon.svelte';

	import type { RangePreset } from './chart';

	export let preset: RangePreset = '3h';
	export let customStartMs = 0;
	export let customEndMs = 0;
	export let onChange: (next: {
		preset: RangePreset;
		startMs: number;
		endMs: number;
		label: string;
	}) => void = () => {};

	const todayIso = new Date().toISOString().slice(0, 10);
	const threeDaysAgoIso = new Date(Date.now() - 3 * 86_400_000).toISOString().slice(0, 10);

	let pickerValue = [parseDate(threeDaysAgoIso), parseDate(todayIso)];
	let customLabel = '';

	const presets: { key: Exclude<RangePreset, 'custom' | '7d'>; label: string }[] = [
		{ key: '1h', label: 'Live · 1h' },
		{ key: '3h', label: 'Live · 3h' },
		{ key: '24h', label: 'Live · 24h' }
	];

	function selectPreset(next: Exclude<RangePreset, 'custom' | '7d'>) {
		preset = next;
		const now = Date.now();
		const hours = next === '1h' ? 1 : next === '3h' ? 3 : 24;
		onChange({
			preset: next,
			startMs: now - hours * 3_600_000,
			endMs: now,
			label: presets.find((p) => p.key === next)?.label ?? next
		});
	}

	function handleValueChange(details: DatePickerValueChangeDetails) {
		pickerValue = details.value;
		if (details.value.length >= 2 && details.value[0] && details.value[1]) {
			const startStr = details.valueAsString[0];
			const endStr = details.valueAsString[1];
			const sMs = new Date(`${startStr}T00:00:00`).getTime();
			const eMs = new Date(`${endStr}T23:59:59`).getTime();
			if (Number.isFinite(sMs) && Number.isFinite(eMs) && eMs > sMs) {
				preset = 'custom';
				customStartMs = sMs;
				customEndMs = eMs;
				customLabel = `${startStr} → ${endStr}`;
				onChange({
					preset: 'custom',
					startMs: sMs,
					endMs: eMs,
					label: customLabel
				});
			}
		}
	}
</script>

<DatePicker.Root
	selectionMode="range"
	value={pickerValue}
	onValueChange={handleValueChange}
	positioning={{ placement: 'bottom-end', gutter: 6 }}
>
	<div class="chips" role="radiogroup" aria-label="Time window">
		{#each presets as p (p.key)}
			<button
				class="chip"
				class:is-on={preset === p.key}
				type="button"
				aria-pressed={preset === p.key}
				on:click={() => selectPreset(p.key)}
			>
				{p.label}
			</button>
		{/each}
		<DatePicker.Trigger
			class="chip dp-trigger {preset === 'custom' ? 'is-on' : ''}"
			aria-label="Pick custom date range"
		>
			<Icon name="clock" size={13} />
			<span>{preset === 'custom' && customLabel ? customLabel : 'Date range'}</span>
		</DatePicker.Trigger>
	</div>

	<Portal>
			<DatePicker.Positioner class="dp-positioner">
				<DatePicker.Content class="dp-content">
					<DatePicker.View view="day">
						<DatePicker.Context>
							{#snippet render(datePicker)}
								<DatePicker.ViewControl class="dp-head">
									<DatePicker.PrevTrigger class="dp-nav" aria-label="Previous month">
										‹
									</DatePicker.PrevTrigger>
									<DatePicker.ViewTrigger class="dp-view-btn">
										<DatePicker.RangeText />
									</DatePicker.ViewTrigger>
									<DatePicker.NextTrigger class="dp-nav" aria-label="Next month">
										›
									</DatePicker.NextTrigger>
								</DatePicker.ViewControl>

								<DatePicker.Table class="dp-table">
									<DatePicker.TableHead>
										<DatePicker.TableRow>
											{#each datePicker().weekDays as weekDay (weekDay.long)}
												<DatePicker.TableHeader class="dp-th">
													{weekDay.narrow}
												</DatePicker.TableHeader>
											{/each}
										</DatePicker.TableRow>
									</DatePicker.TableHead>
									<DatePicker.TableBody>
										{#each datePicker().weeks as week, wi (wi)}
											<DatePicker.TableRow>
												{#each week as day (day.toString())}
													<DatePicker.TableCell value={day} class="dp-cell">
														<DatePicker.TableCellTrigger class="dp-day">
															{day.day}
														</DatePicker.TableCellTrigger>
													</DatePicker.TableCell>
												{/each}
											</DatePicker.TableRow>
										{/each}
									</DatePicker.TableBody>
								</DatePicker.Table>
							{/snippet}
						</DatePicker.Context>
					</DatePicker.View>

					<DatePicker.View view="month">
						<DatePicker.Context>
							{#snippet render(datePicker)}
								<DatePicker.ViewControl class="dp-head">
									<DatePicker.PrevTrigger class="dp-nav">‹</DatePicker.PrevTrigger>
									<DatePicker.ViewTrigger class="dp-view-btn">
										<DatePicker.RangeText />
									</DatePicker.ViewTrigger>
									<DatePicker.NextTrigger class="dp-nav">›</DatePicker.NextTrigger>
								</DatePicker.ViewControl>
								<DatePicker.Table class="dp-table">
									<DatePicker.TableBody>
										{#each datePicker().getMonthsGrid({ columns: 4, format: 'short' }) as months, mi (mi)}
											<DatePicker.TableRow>
												{#each months as month (month.value)}
													<DatePicker.TableCell value={month.value}>
														<DatePicker.TableCellTrigger class="dp-day">
															{month.label}
														</DatePicker.TableCellTrigger>
													</DatePicker.TableCell>
												{/each}
											</DatePicker.TableRow>
										{/each}
									</DatePicker.TableBody>
								</DatePicker.Table>
							{/snippet}
						</DatePicker.Context>
					</DatePicker.View>

					<div class="dp-foot">
						<DatePicker.PresetTrigger value="last7Days" class="dp-preset">
							Last 7 days
						</DatePicker.PresetTrigger>
						<DatePicker.PresetTrigger value="last30Days" class="dp-preset">
							Last 30 days
						</DatePicker.PresetTrigger>
					</div>
				</DatePicker.Content>
			</DatePicker.Positioner>
		</Portal>
</DatePicker.Root>

<style lang="scss">
	@use 'mixins' as *;

	:global([data-scope='date-picker'][data-part='positioner']) {
		z-index: 75;
	}

	:global([data-scope='date-picker'][data-part='content']) {
		@include cut-panel(14px, var(--tw-well), var(--tw-border), 1.5px);
		padding: 14px;
		color: var(--tw-text);
		box-shadow: var(--tw-shadow);
		min-width: 276px;
	}

	:global([data-scope='date-picker'][data-part='content'][hidden]),
	:global([data-scope='date-picker'][data-part='view'][hidden]),
	:global([data-scope='date-picker'][data-part='positioner'][hidden]) {
		display: none !important;
	}

	:global([data-scope='date-picker'][data-part='view-control']) {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
		margin-bottom: 10px;
	}

	:global([data-scope='date-picker'][data-part='prev-trigger']),
	:global([data-scope='date-picker'][data-part='next-trigger']) {
		display: grid;
		place-items: center;
		width: 28px;
		height: 28px;
		border: 1px solid var(--tw-border);
		background: var(--tw-raised);
		color: var(--tw-text);
		font: 700 15px/1 var(--tw-mono);
		cursor: pointer;
	}

	:global([data-scope='date-picker'][data-part='view-trigger']) {
		border: 0;
		background: none;
		color: var(--tw-text);
		font: 700 13px/1 var(--tw-heading);
		cursor: pointer;
	}

	:global([data-scope='date-picker'][data-part='table']) {
		width: 100%;
		border-collapse: collapse;
	}

	:global([data-scope='date-picker'][data-part='table-header']) {
		padding: 4px 0 6px;
		font: 700 11px/1 var(--tw-mono);
		color: var(--tw-muted);
		text-align: center;
	}

	:global([data-scope='date-picker'][data-part='table-cell']) {
		padding: 1px;
		text-align: center;
	}

	:global([data-scope='date-picker'][data-part='table-cell-trigger']) {
		display: inline-grid;
		place-items: center;
		width: 34px;
		height: 30px;
		border: 0;
		background: transparent;
		color: var(--tw-text);
		font: 600 12px/1 var(--tw-mono);
		cursor: pointer;
	}

	:global([data-scope='date-picker'][data-part='table-cell-trigger']:hover) {
		background: color-mix(in srgb, var(--tw-text) 10%, transparent);
	}

	:global([data-scope='date-picker'][data-part='table-cell-trigger'][data-in-range]) {
		background: color-mix(in srgb, var(--tw-accent) 22%, transparent);
	}

	:global([data-scope='date-picker'][data-part='table-cell-trigger'][data-selected]) {
		background: var(--tw-accent);
		color: var(--tw-well);
		font-weight: 700;
	}

	:global([data-scope='date-picker'][data-part='table-cell-trigger'][data-outside-range]) {
		opacity: 0.35;
	}

	.dp-foot {
		display: flex;
		gap: 8px;
		margin-top: 10px;
		padding-top: 10px;
		border-top: 1px solid var(--tw-line-hair);
	}

	:global([data-scope='date-picker'][data-part='preset-trigger']) {
		flex: 1;
		height: 28px;
		border: 1px solid var(--tw-border);
		background: var(--tw-raised);
		color: var(--tw-text);
		font: 700 11px/1 var(--tw-mono);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		cursor: pointer;
	}

	:global([data-scope='date-picker'][data-part='preset-trigger']:hover) {
		border-color: var(--tw-accent);
		color: var(--tw-accent);
	}
</style>
