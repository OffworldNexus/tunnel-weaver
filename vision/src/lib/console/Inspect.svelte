<script lang="ts">
	/**
	 * Request inspection drawer built on `@harshmandan/svaul` (`direction="right"`):
	 * - Removes owner, organisation and per-query reputation score.
	 * - Renders a Flux-Capacitor Y-junction byte diagram (Public Edge In/Out/Total +
	 *   Origin In/Out/Total converging into the Mux Tunnel On-the-Wire In/Out/Total
	 *   with equal-height visual segment bars).
	 * - Aligns Request and Response header tables with an identical 168px name column.
	 * - Syntax-highlights JSON, HTML, CSS and JS response bodies, offers a download
	 *   action when the payload is large, and provides clipboard copy buttons for
	 *   both the response body and the cURL reproduction command.
	 */
	import Drawer from '@harshmandan/svaul';

	import { notify } from '#lib/account/notices';
	import { bytes, clock, ms } from '#lib/mock/format';
	import { inspecting, machines } from '#lib/mock/store';
	import Icon from '#lib/ui/Icon.svelte';
	import Keycap from '#lib/ui/Keycap.svelte';

	import { statusColor } from './palette';
	import Toggle from './Toggle.svelte';

	let blurEvidence = true;

	$: entry = $inspecting;
	$: drawerOpen = Boolean(entry);

	$: ctx = (() => {
		if (!entry) {
			return null;
		}
		const machine = $machines.find((m) => m.id === entry.machineId);
		const service = machine?.services.find((s) => s.id === entry.serviceId);
		return { machine, service };
	})();

	function handleOpenChange(next: boolean) {
		if (!next) {
			inspecting.set(null);
		}
	}

	function close() {
		inspecting.set(null);
	}

	// ---- Flux-capacitor byte metrics ------------------------------------------
	$: edgeTotal = (entry?.bytesIn ?? 0) + (entry?.bytesOut ?? 0);
	$: inShare = edgeTotal > 0 ? Math.max(8, Math.min(92, ((entry?.bytesIn ?? 0) / edgeTotal) * 100)) : 25;
	$: wireTotal = entry?.onTheWire ?? 0;
	$: wireRatio = edgeTotal > 0 ? wireTotal / edgeTotal : 0.55;
	$: wireIn = Math.round((entry?.bytesIn ?? 0) * wireRatio);
	$: wireOut = Math.max(0, wireTotal - wireIn);
	$: wireSavedPct = edgeTotal > 0 ? Math.max(0, Math.round((1 - wireRatio) * 100)) : 0;

	$: isLargePayload = (entry?.bytesOut ?? 0) > 32 * 1024;

	function curlCommand(): string {
		if (!entry || !ctx?.service) {
			return '';
		}
		return `curl -X ${entry.method} 'https://${ctx.service.hostname}${entry.path}' \\\n  -H 'user-agent: ${entry.userAgent}' \\\n  -H 'accept-encoding: zstd, gzip'`;
	}

	async function copyText(text: string, label: string) {
		try {
			await navigator.clipboard.writeText(text);
		} catch {
			// Fallback if clipboard permission is restricted
		}
		notify('success', `${label} copied to clipboard.`);
	}

	function downloadPayload() {
		if (!entry) {
			return;
		}
		const blob = new Blob([entry.responseBody || ''], {
			type: entry.contentType || 'application/octet-stream'
		});
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `${entry.id}-payload.${
			entry.contentType.includes('json')
				? 'json'
				: entry.contentType.includes('html')
					? 'html'
					: entry.contentType.includes('javascript')
						? 'js'
						: entry.contentType.includes('css')
							? 'css'
							: 'bin'
		}`;
		a.click();
		URL.revokeObjectURL(url);
		notify('success', `Downloaded ${bytes(entry.bytesOut)} payload.`);
	}

	// ---- Lightweight syntax tokenizer (no {@html} needed) ---------------------
	interface Token {
		text: string;
		kind: 'plain' | 'key' | 'string' | 'number' | 'keyword' | 'tag' | 'comment';
	}

	function tokenizeBody(code: string, contentType: string): Token[] {
		if (!code) {
			return [];
		}
		const tokens: Token[] = [];
		const isJson = contentType.includes('json') || code.trimStart().startsWith('{');
		const isHtml = contentType.includes('html') || code.trimStart().startsWith('<');
		const isCss = contentType.includes('css');

		const pattern = isJson
			? /("(?:\\.|[^"\\])*"\s*:)|("(?:\\.|[^"\\])*")|(\b(?:true|false|null)\b)|(-?\b\d+(?:\.\d+)?\b)/g
			: isHtml
				? /(<!--[\s\S]*?-->)|(<\/?[a-zA-Z0-9-]+|\s+[a-zA-Z-]+(?==)|\/?>)|("(?:\\.|[^"\\])*")/g
				: isCss
					? /(\/\*[\s\S]*?\*\/)|(--[a-zA-Z0-9-]+|[a-zA-Z-]+(?=\s*:))|(#[0-9a-fA-F]{3,8}|\b\d+(?:px|rem|em|%|ms|s)\b)/g
					: /(\/\/[^\n]*)|("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|(\b(?:export|async|function|const|let|var|await|return|if|else|true|false|null)\b)|(\b\d+(?:\.\d+)?\b)/g;

		let lastIdx = 0;
		let m: RegExpExecArray | null;
		while ((m = pattern.exec(code)) !== null) {
			if (m.index > lastIdx) {
				tokens.push({ text: code.slice(lastIdx, m.index), kind: 'plain' });
			}
			if (isJson) {
				if (m[1]) {
					tokens.push({ text: m[1], kind: 'key' });
				} else if (m[2]) {
					tokens.push({ text: m[2], kind: 'string' });
				} else if (m[3]) {
					tokens.push({ text: m[3], kind: 'keyword' });
				} else {
					tokens.push({ text: m[0], kind: 'number' });
				}
			} else if (isHtml) {
				if (m[1]) {
					tokens.push({ text: m[1], kind: 'comment' });
				} else if (m[2]) {
					tokens.push({ text: m[2], kind: 'tag' });
				} else {
					tokens.push({ text: m[0], kind: 'string' });
				}
			} else if (isCss) {
				if (m[1]) {
					tokens.push({ text: m[1], kind: 'comment' });
				} else if (m[2]) {
					tokens.push({ text: m[2], kind: 'key' });
				} else {
					tokens.push({ text: m[0], kind: 'number' });
				}
			} else {
				if (m[1]) {
					tokens.push({ text: m[1], kind: 'comment' });
				} else if (m[2]) {
					tokens.push({ text: m[2], kind: 'string' });
				} else if (m[3]) {
					tokens.push({ text: m[3], kind: 'keyword' });
				} else {
					tokens.push({ text: m[0], kind: 'number' });
				}
			}
			lastIdx = pattern.lastIndex;
		}
		if (lastIdx < code.length) {
			tokens.push({ text: code.slice(lastIdx), kind: 'plain' });
		}
		return tokens;
	}

	$: bodyTokens = entry ? tokenizeBody(entry.responseBody, entry.contentType) : [];
</script>

<Drawer
	open={drawerOpen}
	onOpenChange={handleOpenChange}
	direction="right"
	class="svaul-inspect-drawer"
>
	{#snippet handle()}{/snippet}
	{#if entry}
		<header class="drawer__head">
			<div class="drawer__title">
				<span class="method mono" style="color: {statusColor(entry.status)}">{entry.method}</span>
				<span class="path mono">{entry.path}</span>
			</div>
			<button class="close" type="button" on:click={close} aria-label="Close">
				<Icon name="close" size={18} />
			</button>
		</header>

		<div class="drawer__body">
			<div class="hero">
				<span class="hero__status" style="color: {statusColor(entry.status)}">{entry.status}</span>
				<div class="hero__meta">
					<span class="mono">{ctx?.service?.hostname ?? '—'}</span>
					<span class="muted">{clock(entry.ts)} · {ms(entry.durationMs)}</span>
				</div>
			</div>

			{#if entry.infraction}
				<div class="infraction-banner" role="status">
					<Icon name="flag" size={16} />
					<span>
						<strong>Infraction:</strong> <span class="mono">{entry.infraction}</span>
					</span>
				</div>
			{/if}

			{#if entry.imagePreview}
				<section class="block">
					<div class="block__head">
						<h3 class="block__title">Captured visual payload</h3>
						<Toggle
							bind:checked={blurEvidence}
							compact
							label={blurEvidence ? 'Blurred' : 'Revealed'}
						/>
					</div>
					<div class="evidence-preview" class:is-blurred={blurEvidence}>
						<img src={entry.imagePreview} alt={entry.infraction || 'Captured image'} />
						<span class="evidence-preview__tag mono">
							<Icon name="flag" size={12} /> {entry.infraction || 'IMAGE PAYLOAD'}
						</span>
					</div>
				</section>
			{/if}

			<dl class="facts">
				<div><dt>Machine</dt><dd class="mono">{ctx?.machine?.name ?? '—'}</dd></div>
				<div><dt>Client IP</dt><dd class="mono">{entry.clientIp} · {entry.region}</dd></div>
				<div><dt>Content type</dt><dd class="mono">{entry.contentType}</dd></div>
				<div>
					<dt>User agent</dt>
					<dd class="mono ellipsis" title={entry.userAgent}>{entry.userAgent}</dd>
				</div>
			</dl>

			<!-- Flux-Capacitor Y-junction byte telemetry -->
			<section class="flux" aria-label="Byte transfer telemetry">
				<div class="flux__arms">
					<div class="flux__node">
						<div class="flux__node-head">
							<span class="flux__node-title">Public edge</span>
							<span class="flux__node-sub mono">Client ↔ Relay</span>
						</div>
						<div class="flux__bar" title="Ingress vs Egress">
							<span class="flux__seg flux__seg--in" style="width: {inShare}%"></span>
							<span class="flux__seg flux__seg--out" style="width: {100 - inShare}%"></span>
						</div>
						<div class="flux__metrics mono">
							<span><i class="dot dot--in"></i>IN {bytes(entry.bytesIn)}</span>
							<span><i class="dot dot--out"></i>OUT {bytes(entry.bytesOut)}</span>
							<strong class="flux__total">Σ {bytes(edgeTotal)}</strong>
						</div>
					</div>

					<div class="flux__node">
						<div class="flux__node-head">
							<span class="flux__node-title">Local origin</span>
							<span class="flux__node-sub mono">Weaver ↔ {ctx?.service?.target ?? 'origin'}</span>
						</div>
						<div class="flux__bar" title="Proxied In vs Origin Out">
							<span class="flux__seg flux__seg--in" style="width: {inShare}%"></span>
							<span class="flux__seg flux__seg--out" style="width: {100 - inShare}%"></span>
						</div>
						<div class="flux__metrics mono">
							<span><i class="dot dot--in"></i>IN {bytes(entry.bytesIn)}</span>
							<span><i class="dot dot--out"></i>OUT {bytes(entry.bytesOut)}</span>
							<strong class="flux__total">Σ {bytes(edgeTotal)}</strong>
						</div>
					</div>
				</div>

				<!-- Y-junction flux capacitor SVG -->
				<div class="flux__junction" aria-hidden="true">
					<svg viewBox="0 0 460 66" preserveAspectRatio="none">
						<!-- Left arm to center core -->
						<path class="flux__conduit" d="M 110 2 L 110 18 L 230 36" />
						<!-- Right arm to center core -->
						<path class="flux__conduit" d="M 350 2 L 350 18 L 230 36" />
						<!-- Center core down to mux stem -->
						<path class="flux__conduit flux__conduit--wire" d="M 230 36 L 230 64" />
						<!-- Flux core ring & nodes -->
						<circle class="flux__core-outer" cx="230" cy="36" r="11" />
						<circle class="flux__core-inner" cx="230" cy="36" r="4.5" />
						<circle class="flux__terminal" cx="110" cy="6" r="3" />
						<circle class="flux__terminal" cx="350" cy="6" r="3" />
						<circle class="flux__terminal flux__terminal--wire" cx="230" cy="60" r="3.5" />
					</svg>
					<span class="flux__badge mono">zstd mux · −{wireSavedPct}%</span>
				</div>

				<div class="flux__node flux__node--wire">
					<div class="flux__node-head">
						<span class="flux__node-title">On the wire · Mux tunnel</span>
						<span class="flux__node-sub mono">Relay ⇄ Weaver (compressed bidirectional stream)</span>
					</div>
					<div class="flux__bar">
						<span class="flux__seg flux__seg--in" style="width: {inShare}%"></span>
						<span class="flux__seg flux__seg--wire" style="width: {100 - inShare}%"></span>
					</div>
					<div class="flux__metrics mono">
						<span><i class="dot dot--in"></i>WIRE IN {bytes(wireIn)}</span>
						<span><i class="dot dot--wire"></i>WIRE OUT {bytes(wireOut)}</span>
						<strong class="flux__total">Σ {bytes(wireTotal)}</strong>
					</div>
				</div>
			</section>

			<section class="block">
				<h3 class="block__title">Request headers</h3>
				<table class="kv">
					<tbody>
						{#each entry.requestHeaders as [k, v] (k)}
							<tr><th class="mono">{k}</th><td class="mono">{v}</td></tr>
						{/each}
					</tbody>
				</table>
			</section>

			{#if entry.requestBody}
				<section class="block">
					<h3 class="block__title">Request body</h3>
					<pre class="code mono">{entry.requestBody}</pre>
				</section>
			{/if}

			<section class="block">
				<h3 class="block__title">Response headers</h3>
				<table class="kv">
					<tbody>
						{#each entry.responseHeaders as [k, v] (k)}
							<tr><th class="mono">{k}</th><td class="mono">{v}</td></tr>
						{/each}
					</tbody>
				</table>
			</section>

			<section class="block">
				<div class="block__head">
					<h3 class="block__title">
						Response body <span class="muted mono">({entry.contentType} · {bytes(entry.bytesOut)})</span>
					</h3>
					<div class="block__actions">
						{#if isLargePayload}
							<Keycap type="button" size="sm" variant="primary" onclick={downloadPayload}>
								<Icon name="download" size={13} /> Download ({bytes(entry.bytesOut)})
							</Keycap>
						{/if}
						<Keycap
							type="button"
							size="sm"
							variant="key"
							onclick={() => copyText(entry?.responseBody ?? '', 'Response body')}
						>
							<Icon name="copy" size={13} /> Copy
						</Keycap>
					</div>
				</div>
				{#if isLargePayload}
					<div class="large-notice">
						<span>
							Large response payload (<strong class="mono">{bytes(entry.bytesOut)}</strong>). Preview
							shown below; download the full payload for offline analysis.
						</span>
					</div>
				{/if}
				<pre class="code mono">{#each bodyTokens as tok, i (i)}<span class="tok-{tok.kind}">{tok.text}</span>{/each}</pre>
			</section>

			<section class="block">
				<div class="block__head">
					<h3 class="block__title">Reproduce (cURL)</h3>
					<Keycap
						type="button"
						size="sm"
						variant="key"
						onclick={() => copyText(curlCommand(), 'cURL command')}
					>
						<Icon name="copy" size={13} /> Copy cURL
					</Keycap>
				</div>
				<pre class="code mono">{curlCommand()}</pre>
			</section>
		</div>
	{/if}
</Drawer>

<style lang="scss">
	@use 'mixins' as *;

	:global([data-svaul-drawer-overlay]) {
		background: rgb(11 6 4 / 0.55) !important;
		backdrop-filter: blur(1.5px);
		z-index: 65 !important;
	}

	:global(.svaul-inspect-drawer) {
		--tw-key-pedestal: #524943;
		width: min(600px, 94vw) !important;
		max-width: 100vw;
		height: 100svh !important;
		display: flex !important;
		flex-direction: column !important;
		background: var(--tw-well) !important;
		color: var(--tw-text) !important;
		border-left: 1.5px solid var(--tw-border) !important;
		border-radius: 0 !important;
		box-shadow: var(--tw-shadow) !important;
		z-index: 70 !important;
		padding: 0 !important;
	}

	.drawer__head {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 12px;
		padding: 14px 16px;
		border-bottom: 1.5px solid var(--tw-border);
		flex: none;
	}

	.drawer__title {
		display: flex;
		align-items: baseline;
		gap: 10px;
		min-width: 0;
	}

	.method {
		font-size: 13px;
		font-weight: 700;
	}

	.path {
		font-size: 14px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.close {
		display: grid;
		place-items: center;
		width: 34px;
		height: 34px;
		border: 0;
		background: none;
		color: var(--tw-muted);
		cursor: pointer;
	}

	.close:hover {
		background: color-mix(in srgb, var(--tw-text) 8%, transparent);
		color: var(--tw-text);
	}

	.drawer__body {
		padding: 16px;
		overflow-y: auto;
		display: flex;
		flex-direction: column;
		gap: 18px;
		flex: 1 1 auto;
	}

	.hero {
		display: flex;
		align-items: center;
		gap: 14px;
	}

	.hero__status {
		font-family: var(--tw-mono);
		font-size: 30px;
		font-weight: 700;
		line-height: 1;
	}

	.hero__meta {
		display: flex;
		flex-direction: column;
		min-width: 0;
		font-size: 13px;
	}

	.hero__meta .mono {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.infraction-banner {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 10px 12px;
		border: 1.5px solid var(--tw-danger);
		background: color-mix(in srgb, var(--tw-danger) 12%, transparent);
		color: var(--tw-danger);
		font-size: 13px;
	}

	.evidence-preview {
		position: relative;
		border: 1.5px solid var(--tw-danger);
		background: #0b0604;
		overflow: hidden;
	}

	.evidence-preview img {
		display: block;
		width: 100%;
		height: auto;
		transition: filter 160ms ease;
	}

	.evidence-preview.is-blurred img {
		filter: blur(12px) contrast(0.85);
	}

	.evidence-preview__tag {
		position: absolute;
		top: 8px;
		left: 8px;
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 3px 8px;
		background: rgb(11 6 4 / 0.9);
		border: 1px solid var(--tw-danger);
		color: var(--tw-danger);
		font-size: 11px;
		font-weight: 700;
	}

	.facts {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 10px 18px;
		margin: 0;
	}

	.facts div {
		display: flex;
		flex-direction: column;
		gap: 2px;
		min-width: 0;
	}

	.facts dt {
		font-size: 11px;
		font-weight: 700;
		letter-spacing: 0.06em;
		text-transform: uppercase;
		color: var(--tw-muted);
	}

	.facts dd {
		margin: 0;
		font-size: 13px;
		overflow-wrap: anywhere;
	}

	.ellipsis {
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	/* ---- Flux-Capacitor Y-junction byte diagram ---- */
	.flux {
		display: flex;
		flex-direction: column;
		padding: 12px;
		border: 1.5px solid var(--tw-border);
		background: var(--tw-raised);
	}

	.flux__arms {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 10px;
	}

	.flux__node {
		@include cut-panel(10px, var(--tw-well), var(--tw-border), 1.5px);
		padding: 10px 12px;
		display: flex;
		flex-direction: column;
		gap: 7px;
	}

	.flux__node--wire {
		--tw-border: var(--tw-confirm);
	}

	.flux__node-head {
		display: flex;
		flex-direction: column;
		gap: 1px;
	}

	.flux__node-title {
		font-size: 11px;
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.06em;
	}

	.flux__node-sub {
		font-size: 10px;
		color: var(--tw-muted);
	}

	/* Equal-height visual segment bar on all three nodes */
	.flux__bar {
		display: flex;
		height: 10px;
		border-radius: 2px;
		overflow: hidden;
		background: var(--tw-deck);
		gap: 1px;
	}

	.flux__seg {
		height: 100%;
	}

	.flux__seg--in {
		background: var(--tw-c2);
	}

	.flux__seg--out {
		background: var(--tw-c1);
	}

	.flux__seg--wire {
		background: var(--tw-c5);
	}

	.flux__metrics {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 6px 10px;
		font-size: 11px;
		color: var(--tw-muted);
	}

	.flux__total {
		margin-left: auto;
		color: var(--tw-text);
		font-size: 12px;
	}

	.dot {
		display: inline-block;
		width: 6px;
		height: 6px;
		margin-right: 4px;
		vertical-align: middle;
	}

	.dot--in {
		background: var(--tw-c2);
	}

	.dot--out {
		background: var(--tw-c1);
	}

	.dot--wire {
		background: var(--tw-c5);
	}

	.flux__junction {
		position: relative;
		height: 62px;
	}

	.flux__junction svg {
		display: block;
		width: 100%;
		height: 100%;
	}

	.flux__conduit {
		fill: none;
		stroke: var(--tw-border);
		stroke-width: 2;
		stroke-dasharray: 4 3;
	}

	.flux__conduit--wire {
		stroke: var(--tw-confirm);
		stroke-width: 2.5;
		stroke-dasharray: none;
	}

	.flux__core-outer {
		fill: var(--tw-well);
		stroke: var(--tw-accent);
		stroke-width: 2;
	}

	.flux__core-inner {
		fill: var(--tw-confirm);
	}

	.flux__terminal {
		fill: var(--tw-c1);
	}

	.flux__terminal--wire {
		fill: var(--tw-confirm);
	}

	.flux__badge {
		position: absolute;
		top: 50%;
		right: 8px;
		transform: translateY(-50%);
		padding: 2px 7px;
		border: 1px solid var(--tw-confirm);
		background: var(--tw-well);
		color: var(--tw-confirm);
		font-size: 10px;
		font-weight: 700;
	}

	/* ---- Aligned headers & syntax-highlighted code ---- */
	.block {
		display: flex;
		flex-direction: column;
		gap: 8px;
	}

	.block__head {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: 10px;
	}

	.block__title {
		font-family: var(--tw-heading);
		font-size: 13px;
		font-weight: 700;
		margin: 0;
	}

	.block__title .muted {
		font-weight: 400;
		font-size: 11px;
	}

	.block__actions {
		display: flex;
		align-items: center;
		gap: 8px;
	}

	/* Fixed 168px header-name column so Request and Response header tables align identically */
	.kv {
		width: 100%;
		table-layout: fixed;
		border-collapse: collapse;
		font-size: 12px;
		border-top: 1px solid var(--tw-line-hair);
	}

	.kv th {
		width: 168px;
		text-align: left;
		font-weight: 700;
		color: var(--tw-muted);
		padding: 6px 12px 6px 0;
		vertical-align: top;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}

	.kv td {
		padding: 6px 0;
		overflow-wrap: anywhere;
		vertical-align: top;
	}

	.kv tr {
		border-bottom: 1px solid var(--tw-line-hair);
	}

	.large-notice {
		padding: 8px 10px;
		border: 1px dashed var(--tw-border);
		background: var(--tw-raised);
		font-size: 12px;
		color: var(--tw-muted);
	}

	.code {
		margin: 0;
		padding: 12px;
		border: 1.5px solid var(--tw-border);
		background: var(--tw-raised);
		font-size: 12px;
		line-height: 1.55;
		overflow-x: auto;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
	}

	.tok-key {
		color: var(--tw-accent);
		font-weight: 700;
	}

	.tok-string {
		color: var(--tw-c2);
	}

	.tok-number {
		color: var(--tw-c1);
		font-weight: 700;
	}

	.tok-keyword,
	.tok-tag {
		color: var(--tw-info);
		font-weight: 700;
	}

	.tok-comment {
		color: var(--tw-muted);
		font-style: italic;
	}
</style>
