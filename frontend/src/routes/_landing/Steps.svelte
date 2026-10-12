<script lang="ts">
	import Section from './Section.svelte';

	// Landing copy, kept next to the section that renders it.
	const steps = [
		{
			n: '01',
			title: 'Run the weaver',
			text: 'Start it next to the service you want to reach — it dials out to the relay, so nothing new is exposed on your network.'
		},
		{
			n: '02',
			title: 'Get a stable hostname',
			text: 'Your service appears at one predictable public hostname, covered by a wildcard certificate. No dynamic DNS, no rebuild on restart.'
		},
		{
			n: '03',
			title: 'Share it',
			text: 'Send the link. Traffic stays end-to-end through the relay, and the name stays the same for as long as you keep the tunnel open.'
		}
	];
</script>

<Section
	id="steps-title"
	title="How it works"
	lede="Three steps from a local service to a shareable link."
	listTag="ol"
>
	{#each steps as step}
		<li class="step">
			<span class="step__num" aria-hidden="true">{step.n}</span>
			<h3 class="step__title">{step.title}</h3>
			<p class="step__text">{step.text}</p>
		</li>
	{/each}
</Section>

<style lang="scss">
	@use 'mixins' as *;

	.step {
		@include cut-panel(16px, var(--tw-well));
		display: flex;
		flex-direction: column;
		gap: 10px;
		padding: 24px 22px 26px;
	}

	.step__num {
		font-family: var(--tw-mono);
		font-size: 13px;
		font-weight: 700;
		letter-spacing: 0.16em;
		color: var(--tw-accent);
	}

	.step__title {
		font-family: var(--tw-heading);
		font-size: 19px;
		font-weight: 700;
		line-height: 1.25;
	}

	.step__text {
		color: var(--tw-muted);
		font-size: 15px;
		line-height: 1.6;
	}
</style>
