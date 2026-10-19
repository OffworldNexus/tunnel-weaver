<script lang="ts">
	import Icon from '#lib/ui/Icon.svelte';

	import Section from './Section.svelte';

	// Landing copy, kept next to the section that renders it.
	const benefits = [
		{
			icon: 'plug',
			title: 'No port-forwarding',
			text: 'The weaver dials out. Keep your firewall closed.'
		},
		{
			icon: 'lock',
			title: 'TLS by default',
			text: 'Every hostname is served over HTTPS automatically.'
		},
		{
			icon: 'globe',
			title: 'One hostname per service',
			text: 'A flat, readable name for each thing you run.'
		},
		{
			icon: 'battery',
			title: 'Batteries included',
			text: 'TLS, DNS, certificates and abuse protection ship with the relay — nothing extra to run.'
		}
	] as const;
</script>

<Section
	id="benefits-title"
	title="Why Tunnel Weaver"
	lede="Small pieces that keep the operation boring."
	cardsMin="220px"
>
	{#each benefits as benefit (benefit.title)}
		<li class="benefit">
			<span class="benefit__icon"><Icon name={benefit.icon} /></span>
			<div>
				<p class="benefit__title">{benefit.title}</p>
				<p class="benefit__text">{benefit.text}</p>
			</div>
		</li>
	{/each}
</Section>

<style lang="scss">
	@use 'mixins' as *;

	.benefit {
		@include cut-panel(12px, color-mix(in srgb, var(--tw-well) 55%, var(--tw-deck)));
		display: flex;
		align-items: flex-start;
		gap: 12px;
		padding: 18px;
	}

	.benefit__icon {
		display: grid;
		place-items: center;
		width: 34px;
		height: 34px;
		flex: none;
		color: var(--tw-accent);
	}

	.benefit__title {
		font-weight: 700;
		line-height: 1.3;
	}

	.benefit__text {
		margin-top: 4px;
		color: var(--tw-muted);
		font-size: 14px;
		line-height: 1.5;
	}
</style>
