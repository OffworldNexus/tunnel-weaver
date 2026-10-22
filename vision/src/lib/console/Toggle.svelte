<script lang="ts">
	/**
	 * Panel-mounted bat-handle toggle switch in the console's flat-vector Minitel
	 * style: a corner-riveted escutcheon plate, a 3D hexagonal bushing nut with a
	 * center pivot socket, a clear status window, and a tapered bat lever with a
	 * rounded ball tip that swings from left (OFF) to right (ON).
	 */
	export let checked = false;
	export let label = '';
	export let disabled = false;
	export let compact = false;
	export let id: string | undefined = undefined;
	export let onChange: ((checked: boolean) => void) | undefined = undefined;

	function flip() {
		if (disabled) {
			return;
		}
		checked = !checked;
		onChange?.(checked);
	}
</script>

<button
	{id}
	type="button"
	class="bat-switch"
	class:bat-switch--compact={compact}
	role="switch"
	aria-checked={checked}
	{disabled}
	on:click={flip}
>
	<svg
		class="bat-switch__art"
		viewBox="0 0 64 30"
		width={compact ? 54 : 64}
		height={compact ? 25 : 30}
		aria-hidden="true"
		focusable="false"
	>
		<!-- 3D pedestal under the escutcheon plate -->
		<polygon
			class="bat-switch__pedestal"
			points="1,4 57,4 63,10 63,29 1,29"
		/>

		<!-- Escutcheon mounting plate with top-right 45° cut -->
		<polygon
			class="bat-switch__plate"
			points="1,1 57,1 63,7 63,26 1,26"
		/>

		<!-- Active status window on the right half when ON -->
		<polygon
			class="bat-switch__status-on"
			points="32,3.5 55.8,3.5 60.5,8.2 60.5,23.5 32,23.5"
		/>

		<!-- Corner rivets (like the 4 mounting holes on the KN3F plate) -->
		<circle class="bat-switch__rivet" cx="5" cy="5" r="1.1" />
		<circle class="bat-switch__rivet" cx="5" cy="22" r="1.1" />
		<circle class="bat-switch__rivet" cx="59" cy="22" r="1.1" />

		<!-- O / I state stamps on the plate -->
		<circle class="bat-switch__stamp-off" cx="12" cy="13.5" r="3" />
		<line class="bat-switch__stamp-on" x1="51.5" y1="10" x2="51.5" y2="17" />

		<!-- 3D pedestal of the hexagonal bushing nut -->
		<polygon
			class="bat-switch__nut-pedestal"
			points="32,5.5 40.2,10.2 40.2,19.8 32,24.5 23.8,19.8 23.8,10.2"
		/>

		<!-- Hexagonal bushing nut -->
		<polygon
			class="bat-switch__nut"
			points="32,3.5 40.2,8.2 40.2,17.8 32,22.5 23.8,17.8 23.8,8.2"
		/>

		<!-- Threaded bushing collar & dark center pivot socket -->
		<circle class="bat-switch__collar" cx="32" cy="13" r="5.6" />
		<circle class="bat-switch__socket" cx="32" cy="13" r="3.4" />

		<!-- Cast shadow of the bat lever onto the plate, pivoted at socket center (32, 13) -->
		<g transform="translate(32, 15.5)">
			<g class="bat-switch__rotor">
				<path
					class="bat-switch__shadow"
					d="M -1.8 0 L -4.2 -15 A 4.2 4.2 0 1 1 4.2 -15 L 1.8 0 A 1.8 1.8 0 1 1 -1.8 0 Z"
				/>
			</g>
		</g>

		<!-- Tapered bat handle + rounded ball tip pivoting around socket center (32, 13) -->
		<g transform="translate(32, 13)">
			<g class="bat-switch__rotor">
				<path
					class="bat-switch__bat"
					d="M -1.8 0 L -4.2 -15 A 4.2 4.2 0 1 1 4.2 -15 L 1.8 0 A 1.8 1.8 0 1 1 -1.8 0 Z"
				/>
				<!-- Ball-tip specular highlight -->
				<circle class="bat-switch__tip-shine" cx="0" cy="-15.2" r="1.8" />
			</g>
		</g>
	</svg>

	{#if label}<span class="bat-switch__label">{label}</span>{/if}
</button>

<style lang="scss">
	.bat-switch {
		display: inline-flex;
		align-items: center;
		gap: 10px;
		border: 0;
		background: none;
		padding: 0;
		color: var(--tw-text);
		font: 700 13px/1 var(--tw-sans);
		cursor: pointer;
		user-select: none;
	}

	.bat-switch:disabled {
		opacity: 0.45;
		cursor: not-allowed;
	}

	.bat-switch__art {
		display: block;
		flex: none;
		overflow: visible;
	}

	.bat-switch__pedestal {
		fill: var(--tw-key-pedestal);
	}

	.bat-switch__plate {
		fill: var(--tw-key);
		stroke: var(--tw-border);
		stroke-width: 1.5;
		transition:
			fill 130ms ease,
			stroke 130ms ease;
	}

	.bat-switch__status-on {
		fill: var(--tw-confirm);
		opacity: 0;
		transition: opacity 130ms ease;
	}

	.bat-switch[aria-checked='true'] .bat-switch__status-on {
		opacity: 1;
	}

	.bat-switch__rivet {
		fill: var(--tw-border);
	}

	.bat-switch[aria-checked='true'] .bat-switch__rivet:last-of-type {
		fill: var(--tw-on-confirm);
	}

	.bat-switch__stamp-off {
		fill: none;
		stroke: var(--tw-muted);
		stroke-width: 1.5;
		transition: opacity 120ms ease;
	}

	.bat-switch[aria-checked='true'] .bat-switch__stamp-off {
		opacity: 0.45;
	}

	.bat-switch__stamp-on {
		stroke: var(--tw-muted);
		stroke-width: 1.8;
		stroke-linecap: round;
		transition: stroke 120ms ease;
	}

	.bat-switch[aria-checked='true'] .bat-switch__stamp-on {
		stroke: var(--tw-on-confirm);
	}

	.bat-switch__nut-pedestal {
		fill: #0b0604;
	}

	.bat-switch__nut {
		fill: var(--tw-raised);
		stroke: var(--tw-border);
		stroke-width: 1.4;
		stroke-linejoin: round;
	}

	.bat-switch__collar {
		fill: var(--tw-deck);
		stroke: var(--tw-border);
		stroke-width: 1.2;
	}

	.bat-switch__socket {
		fill: #0b0604;
	}

	// The bat lever pivots around local (0, 0) inside the socket at (32, 13):
	// -68deg = thrown left (OFF), +68deg = thrown right (ON)
	.bat-switch__rotor {
		transform-origin: 0 0;
		transform: rotate(-68deg);
		transition: transform 160ms cubic-bezier(0.22, 1.35, 0.36, 1);
	}

	.bat-switch[aria-checked='true'] .bat-switch__rotor {
		transform: rotate(68deg);
	}

	.bat-switch__shadow {
		fill: rgb(0 0 0 / 0.55);
	}

	.bat-switch__bat {
		fill: var(--tw-muted);
		stroke: #0b0604;
		stroke-width: 1.4;
		transition:
			fill 130ms ease,
			stroke 130ms ease;
	}

	.bat-switch[aria-checked='true'] .bat-switch__bat {
		fill: var(--tw-text);
		stroke: var(--tw-on-confirm);
	}

	.bat-switch__tip-shine {
		fill: var(--tw-well);
		opacity: 0.45;
	}

	.bat-switch[aria-checked='true'] .bat-switch__tip-shine {
		fill: var(--tw-confirm);
		opacity: 1;
	}

	.bat-switch:hover:not(:disabled) .bat-switch__plate {
		stroke: var(--tw-accent);
	}

	@media (prefers-reduced-motion: reduce) {
		.bat-switch__rotor,
		.bat-switch__status-on,
		.bat-switch__bat {
			transition: none;
		}
	}
</style>
