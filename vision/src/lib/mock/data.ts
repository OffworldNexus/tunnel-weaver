/**
 * The seed data for the vision mock.
 *
 * A small seeded PRNG keeps the generated traffic shapes stable across reloads
 * so screenshots and reviews stay comparable. Nothing here talks to a server:
 * `store.ts` owns the only mutable copy.
 */
import type {
	CodeClass,
	LogEntry,
	Machine,
	Org,
	PathStat,
	Person,
	ReviewItem,
	Service,
	TrafficPoint
} from './types';

/** The tunnel domain every public hostname sits under. */
export const ROOT = 'wvr.run';

const MINUTE = 60_000;

/** mulberry32: a tiny deterministic PRNG so the seed is reproducible. */
function rng(seed: number): () => number {
	let a = seed >>> 0;
	return () => {
		a = (a + 0x6d2b79f5) >>> 0;
		let t = a;
		t = Math.imul(t ^ (t >>> 15), t | 1);
		t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
		return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
	};
}

let seq = 0;
export function nextId(prefix: string): string {
	seq += 1;
	return `${prefix}_${seq.toString(36).padStart(4, '0')}`;
}

function iso(msAgo: number): string {
	return new Date(Date.now() - msAgo).toISOString();
}

// ---- traffic shapes -------------------------------------------------------

/** A day/night-ish wave plus noise, so the sparklines read as real traffic. */
function wave(i: number, period: number, phase: number): number {
	return 0.5 + 0.5 * Math.sin((i / period) * Math.PI * 2 + phase);
}

function series(
	seed: number,
	opts: { base: number; amplitude: number; inboundRatio: number; points?: number }
): TrafficPoint[] {
	// 180 minute-by-minute buckets = the default 3-hour floating window.
	const points = opts.points ?? 180;
	const r = rng(seed);
	const out: TrafficPoint[] = [];
	const currentMinute = Math.floor(Date.now() / MINUTE) * MINUTE;
	for (let i = 0; i < points; i += 1) {
		const w = wave(i, 48, seed % 7) * 0.65 + wave(i, 19, (seed * 3) % 11) * 0.35;
		const noise = 0.82 + r() * 0.36;
		const spike = r() > 0.96 ? 1.65 + r() * 0.75 : 1;
		const requests = Math.max(1, Math.round(opts.base * (0.55 + w * 0.9) * noise * spike));
		const bytesOut = Math.round(requests * opts.amplitude * (0.72 + r() * 0.56));
		const bytesIn = Math.round(bytesOut * opts.inboundRatio * (0.72 + r() * 0.52));
		// The mux leg is the same traffic after compression.
		const comp = 0.48 + r() * 0.18;
		out.push({
			ts: currentMinute - (points - 1 - i) * MINUTE,
			bytesIn,
			bytesOut,
			tunIn: Math.round(bytesIn * comp),
			tunOut: Math.round(bytesOut * comp),
			requests
		});
	}
	return out;
}

function aggregateSeries(parts: TrafficPoint[][]): TrafficPoint[] {
	if (parts.length === 0) {
		return [];
	}
	const points = parts[0].length;
	const out: TrafficPoint[] = [];
	for (let i = 0; i < points; i += 1) {
		out.push({
			ts: parts[0][i].ts,
			bytesIn: parts.reduce((s, p) => s + p[i].bytesIn, 0),
			bytesOut: parts.reduce((s, p) => s + p[i].bytesOut, 0),
			tunIn: parts.reduce((s, p) => s + p[i].tunIn, 0),
			tunOut: parts.reduce((s, p) => s + p[i].tunOut, 0),
			requests: parts.reduce((s, p) => s + p[i].requests, 0)
		});
	}
	return out;
}

// ---- service catalog ------------------------------------------------------

interface CatalogEntry {
	name: string;
	target: string;
	paths: string[];
	contentType: string;
	/** Typical response size multiplier for the byte counters. */
	bigness: number;
}

const CATALOG: CatalogEntry[] = [
	{
		name: 'grafana',
		target: 'http://127.0.0.1:3000',
		paths: ['/api/dashboards/uid/home', '/api/ds/query', '/public/build/app.js', '/api/health'],
		contentType: 'application/json',
		bigness: 4
	},
	{
		name: 'homeassistant',
		target: 'http://127.0.0.1:8123',
		paths: ['/api/states', '/api/websocket', '/local/custom.js', '/api/services/light/turn_on'],
		contentType: 'application/json',
		bigness: 2
	},
	{
		name: 'jellyfin',
		target: 'http://127.0.0.1:8096',
		paths: ['/Videos/8a3f/stream', '/Items/Latest', '/System/Info/Public', '/web/index.html'],
		contentType: 'video/mp4',
		bigness: 900
	},
	{
		name: 'nextcloud',
		target: 'http://127.0.0.1:8088',
		paths: ['/remote.php/dav/files', '/index.php/apps/files', '/ocs/v2.php/capabilities'],
		contentType: 'application/xml',
		bigness: 40
	},
	{
		name: 'paperless',
		target: 'http://127.0.0.1:8000',
		paths: ['/api/documents/', '/api/documents/142/thumb', '/api/tags/', '/api/statistics/'],
		contentType: 'application/json',
		bigness: 8
	},
	{
		name: 'vault',
		target: 'http://127.0.0.1:8200',
		paths: ['/v1/sys/health', '/v1/secret/data/app', '/ui/assets/app.js'],
		contentType: 'application/json',
		bigness: 1
	},
	{
		name: 'gitea',
		target: 'http://127.0.0.1:3001',
		paths: ['/api/v1/repos', '/git/offworld/weaver.git/info/refs', '/api/v1/version', '/avatars/7'],
		contentType: 'application/json',
		bigness: 6
	},
	{
		name: 'immich',
		target: 'http://127.0.0.1:2283',
		paths: ['/api/assets/random', '/api/server-info/version', '/api/albums', '/api/search/metadata'],
		contentType: 'image/jpeg',
		bigness: 220
	},
	{
		name: 'n8n',
		target: 'http://127.0.0.1:5678',
		paths: ['/rest/workflows', '/webhook/ingest', '/rest/credentials', '/healthz'],
		contentType: 'application/json',
		bigness: 3
	},
	{
		name: 'pihole',
		target: 'http://127.0.0.1:8053',
		paths: ['/admin/api.php', '/admin/scripts/pi-hole/js/index.js', '/api/stats/summary'],
		contentType: 'application/json',
		bigness: 1
	},
	{
		name: 'code',
		target: 'http://127.0.0.1:8443',
		paths: ['/healthz', '/vscode-remote-resource', '/static/out/vs/workbench.js'],
		contentType: 'text/html',
		bigness: 12
	},
	{
		name: 'minecraft',
		target: 'http://127.0.0.1:25575',
		paths: ['/map/', '/map/tiles/0_0.png', '/status.json'],
		contentType: 'image/png',
		bigness: 90
	},
	{
		name: 'media',
		target: 'http://127.0.0.1:9000',
		paths: ['/media/library', '/media/magnet', '/media/stream/4f2a', '/media/torrent/add'],
		contentType: 'application/octet-stream',
		bigness: 400
	},
	{
		name: 'search',
		target: 'http://127.0.0.1:7700',
		paths: ['/indexes/docs/search', '/health', '/indexes/docs/settings'],
		contentType: 'application/json',
		bigness: 2
	},
	{
		name: 'registry',
		target: 'http://127.0.0.1:5000',
		paths: ['/v2/libs/base/manifests/latest', '/v2/_catalog', '/v2/libs/base/blobs/sha256:9a'],
		contentType: 'application/vnd.oci.image.manifest.v1+json',
		bigness: 60
	},
	{
		name: 'octoprint',
		target: 'http://127.0.0.1:5001',
		paths: ['/api/printer', '/api/job', '/webcam/?action=stream', '/api/files/local'],
		contentType: 'application/json',
		bigness: 5
	},
	{
		name: 'zigbee',
		target: 'http://127.0.0.1:8085',
		paths: ['/api/devices', '/api/networkmap', '/assets/index.js'],
		contentType: 'application/json',
		bigness: 2
	},
	{
		name: 'sync',
		target: 'http://127.0.0.1:8384',
		paths: ['/rest/system/status', '/rest/db/completion', '/rest/events'],
		contentType: 'application/json',
		bigness: 1
	}
];

function catalog(name: string): CatalogEntry {
	return CATALOG.find((c) => c.name === name) ?? CATALOG[0];
}

function codeClasses(requestsHour: number, errorRate: number, seed: number): CodeClass[] {
	const r = rng(seed);
	const errs = Math.round(requestsHour * errorRate);
	const redirects = Math.round(requestsHour * (0.02 + r() * 0.04));
	const ok = Math.max(0, requestsHour - errs - redirects);
	return [
		{ label: '2xx', count: ok },
		{ label: '3xx', count: redirects },
		{ label: '4xx', count: Math.round(errs * 0.7) },
		{ label: '5xx', count: Math.round(errs * 0.3) }
	];
}

function topPaths(entry: CatalogEntry, requestsHour: number, seed: number): PathStat[] {
	const r = rng(seed);
	return entry.paths
		.map((path, i) => ({
			path,
			count: Math.max(1, Math.round((requestsHour / (entry.paths.length + 1)) * (0.6 + r() * 0.9))),
			avgMs: Math.round(4 + r() * (i === 0 ? 60 : 20))
		}))
		.sort((a, b) => b.count - a.count);
}

// ---- machines & services --------------------------------------------------

interface MachineSpec {
	name: string;
	hostname: string;
	os: string;
	version: string;
	online: boolean;
	verified: boolean;
	lastSeenMsAgo: number;
	services: { name: string; tunnel?: Service['tunnel']; reputation?: number; flagged?: boolean }[];
}

function buildService(
	machineId: string,
	personSlug: string,
	machineName: string,
	spec: MachineSpec['services'][number],
	seed: number
): Service {
	const entry = catalog(spec.name);
	const tunnel = spec.tunnel ?? 'open';
	const reputation = spec.reputation ?? Math.round(82 + rng(seed)() * 17);
	const requestsHour = Math.round(80 + rng(seed + 1)() * 4200);
	const errorRate = 0.002 + rng(seed + 2)() * 0.05;
	const s = series(seed, { base: Math.round(requestsHour / 60), amplitude: entry.bigness, inboundRatio: 0.35 });
	const lastHour = s.slice(-60);
	const bytesOut = lastHour.reduce((a, p) => a + p.bytesOut, 0);
	const bytesIn = lastHour.reduce((a, p) => a + p.bytesIn, 0);
	const requests = lastHour.reduce((a, p) => a + p.requests, 0);
	const opened = tunnel === 'open' ? iso(MINUTE * Math.round(30 + rng(seed + 3)() * 20000)) : '';
	return {
		id: nextId('svc'),
		machineId,
		name: spec.name,
		hostname: `${personSlug}-${machineName}-${spec.name}.${ROOT}`,
		target: entry.target,
		tunnel,
		reputation,
		flagged: spec.flagged ?? false,
		verdict: spec.flagged ? 'pending' : reputation < 40 ? 'banned' : 'cleared',
		requests,
		bytesIn,
		bytesOut,
		requestsHour,
		errorRate,
		avgLatencyMs: Math.round(8 + rng(seed + 4)() * 120),
		openedAt: opened,
		series: s,
		codeClasses: codeClasses(requestsHour, errorRate, seed + 5),
		topPaths: topPaths(entry, requestsHour, seed + 6)
	};
}

function buildMachine(personId: string, personSlug: string, spec: MachineSpec, seed: number): Machine {
	const id = nextId('mach');
	const services = spec.services.map((s, i) => buildService(id, personSlug, spec.name, s, seed * 31 + i));
	return {
		id,
		personId,
		name: spec.name,
		hostname: spec.hostname,
		fingerprint: fingerprint(seed),
		os: spec.os,
		agentVersion: spec.version,
		online: spec.online,
		pairedAt: iso(MINUTE * 60 * 24 * Math.round(20 + rng(seed)() * 300)),
		lastSeenAt: iso(spec.lastSeenMsAgo),
		verified: spec.verified,
		services,
		series: aggregateSeries(services.map((s) => s.series))
	};
}

/** A plausible-looking `p256:` fingerprint, grouped in fours. */
function fingerprint(seed: number): string {
	const r = rng(seed + 99);
	let hex = '';
	for (let i = 0; i < 33; i += 1) {
		hex += Math.floor(r() * 256)
			.toString(16)
			.padStart(2, '0');
	}
	return `p256:${hex.match(/.{1,4}/g)?.join(' ') ?? hex}`;
}

// ---- the world ------------------------------------------------------------

export interface Seed {
	orgs: Org[];
	people: Person[];
	machines: Machine[];
	review: ReviewItem[];
}

export function buildSeed(): Seed {
	const orgs: Org[] = [
		{
			id: 'org_northwind',
			name: 'Northwind Robotics',
			slug: 'northwind',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 420),
			contactEmail: 'ops@northwind.example',
			reputation: 88,
			meanResponseMinutes: 22,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'org_helio',
			name: 'Helio Labs',
			slug: 'helio',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 610),
			contactEmail: 'infra@heliolabs.example',
			reputation: 64,
			meanResponseMinutes: 215,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'org_fieldnote',
			name: 'Fieldnote Studio',
			slug: 'fieldnote',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 64),
			contactEmail: 'hello@fieldnote.example',
			reputation: 82,
			meanResponseMinutes: 48,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'org_kestrel',
			name: 'Kestrel Telemetry',
			slug: 'kestrel',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 180),
			contactEmail: 'noc@kestrel.example',
			reputation: 96,
			meanResponseMinutes: 9,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'org_meridian',
			name: 'Meridian Freight',
			slug: 'meridian',
			status: 'suspended',
			createdAt: iso(MINUTE * 60 * 24 * 300),
			contactEmail: 'it@meridian.example',
			reputation: 18,
			meanResponseMinutes: 1640,
			banReason:
				'Org admin failed to act on repeated CSAM perceptual-hash alerts and malware distribution on pavel-ops-media for over 24 hours.',
			bannedAt: iso(MINUTE * 60 * 9),
			bannedSummary:
				'Score at ban: 18/100 · Median response: 27h 20m · 412 visitor fingerprints · CSAM perceptual hash (9), Malware dropper (34) · Raw samples purged on ban.'
		}
	];

	const people: Person[] = [
		// Super admin — global operator, not tied to a tenant org, owns no machines
		{
			id: 'usr_ada',
			orgId: '',
			name: 'Ada Offworld',
			email: 'ada@offworld.example',
			slug: 'ada',
			role: 'super_admin',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 700),
			lastSeenAt: iso(MINUTE * 3),
			reputation: 100,
			demo: true,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		// Northwind Robotics
		{
			id: 'usr_priya',
			orgId: 'org_northwind',
			name: 'Priya Nair',
			email: 'priya@northwind.example',
			slug: 'priya',
			role: 'org_admin',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 410),
			lastSeenAt: iso(MINUTE * 11),
			reputation: 100,
			demo: true,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'usr_sam',
			orgId: 'org_northwind',
			name: 'Sam Okafor',
			email: 'sam@northwind.example',
			slug: 'sam',
			role: 'user',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 380),
			lastSeenAt: iso(MINUTE * 1),
			reputation: 91,
			demo: true,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'usr_elena',
			orgId: 'org_northwind',
			name: 'Elena Rostova',
			email: 'elena@northwind.example',
			slug: 'elena',
			role: 'user',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 310),
			lastSeenAt: iso(MINUTE * 4),
			reputation: 95,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'usr_viktor',
			orgId: 'org_northwind',
			name: 'Viktor Krol',
			email: 'viktor@northwind.example',
			slug: 'viktor',
			role: 'user',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 120),
			lastSeenAt: iso(MINUTE * 2),
			reputation: 26,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'usr_dana',
			orgId: 'org_northwind',
			name: 'Dana Whitlock',
			email: 'dana@northwind.example',
			slug: 'dana',
			role: 'user',
			status: 'suspended',
			createdAt: iso(MINUTE * 60 * 24 * 200),
			lastSeenAt: iso(MINUTE * 60 * 27),
			reputation: 14,
			demo: false,
			banReason:
				'Confirmed PDQ perceptual-hash matches on /media/stream/4f2a and automated distribution to external scrapers. Raw evidence samples purged upon ban.',
			bannedAt: iso(MINUTE * 60 * 27),
			bannedSummary:
				'238 distinct visitor fingerprints · CSAM perceptual hash (6), Automated mirror scraping (19) · Raw samples purged at ban.'
		},
		{
			id: 'usr_lee',
			orgId: 'org_northwind',
			name: 'Lee Zhang',
			email: 'lee@northwind.example',
			slug: 'lee',
			role: 'user',
			status: 'invited',
			createdAt: iso(MINUTE * 60 * 5),
			lastSeenAt: '',
			reputation: 100,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		// Helio Labs
		{
			id: 'usr_marco',
			orgId: 'org_helio',
			name: 'Marco Bellini',
			email: 'marco@heliolabs.example',
			slug: 'marco',
			role: 'org_admin',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 600),
			lastSeenAt: iso(MINUTE * 42),
			reputation: 100,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'usr_yuki',
			orgId: 'org_helio',
			name: 'Yuki Tanaka',
			email: 'yuki@heliolabs.example',
			slug: 'yuki',
			role: 'user',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 500),
			lastSeenAt: iso(MINUTE * 6),
			reputation: 21,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'usr_omar',
			orgId: 'org_helio',
			name: 'Omar Haddad',
			email: 'omar@heliolabs.example',
			slug: 'omar',
			role: 'user',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 90),
			lastSeenAt: iso(MINUTE * 120),
			reputation: 89,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		// Fieldnote Studio
		{
			id: 'usr_ines',
			orgId: 'org_fieldnote',
			name: 'Inès Moreau',
			email: 'ines@fieldnote.example',
			slug: 'ines',
			role: 'org_admin',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 64),
			lastSeenAt: iso(MINUTE * 30),
			reputation: 100,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'usr_theo',
			orgId: 'org_fieldnote',
			name: 'Theo Brandt',
			email: 'theo@fieldnote.example',
			slug: 'theo',
			role: 'user',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 50),
			lastSeenAt: iso(MINUTE * 2),
			reputation: 38,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'usr_clara',
			orgId: 'org_fieldnote',
			name: 'Clara Vance',
			email: 'clara@fieldnote.example',
			slug: 'clara',
			role: 'user',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 45),
			lastSeenAt: iso(MINUTE * 8),
			reputation: 96,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		// Kestrel Telemetry
		{
			id: 'usr_soren',
			orgId: 'org_kestrel',
			name: 'Soren Lind',
			email: 'soren@kestrel.example',
			slug: 'soren',
			role: 'org_admin',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 180),
			lastSeenAt: iso(MINUTE * 18),
			reputation: 100,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'usr_maya',
			orgId: 'org_kestrel',
			name: 'Maya Lin',
			email: 'maya@kestrel.example',
			slug: 'maya',
			role: 'user',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 160),
			lastSeenAt: iso(MINUTE * 5),
			reputation: 97,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		{
			id: 'usr_devon',
			orgId: 'org_kestrel',
			name: 'Devon Brooks',
			email: 'devon@kestrel.example',
			slug: 'devon',
			role: 'user',
			status: 'active',
			createdAt: iso(MINUTE * 60 * 24 * 140),
			lastSeenAt: iso(MINUTE * 60 * 3),
			reputation: 94,
			demo: false,
			banReason: '',
			bannedAt: '',
			bannedSummary: ''
		},
		// Meridian Freight (suspended)
		{
			id: 'usr_greta',
			orgId: 'org_meridian',
			name: 'Greta Lindqvist',
			email: 'greta@meridian.example',
			slug: 'greta',
			role: 'org_admin',
			status: 'suspended',
			createdAt: iso(MINUTE * 60 * 24 * 290),
			lastSeenAt: iso(MINUTE * 60 * 8),
			reputation: 52,
			demo: false,
			banReason: 'Suspended as part of organisation-wide ban on Meridian Freight.',
			bannedAt: iso(MINUTE * 60 * 9),
			bannedSummary: 'Organisation-level enforcement.'
		},
		{
			id: 'usr_pavel',
			orgId: 'org_meridian',
			name: 'Pavel Novák',
			email: 'pavel@meridian.example',
			slug: 'pavel',
			role: 'user',
			status: 'suspended',
			createdAt: iso(MINUTE * 60 * 24 * 250),
			lastSeenAt: iso(MINUTE * 60 * 9),
			reputation: 12,
			demo: false,
			banReason:
				'Hosted CSAM hashes and ELF malware droppers on pavel-ops-media; escalated to full organisation ban after 24h without org-admin action.',
			bannedAt: iso(MINUTE * 60 * 9),
			bannedSummary:
				'412 distinct visitor fingerprints · CSAM perceptual hash (9), Malware dropper (34) · Raw samples purged at ban.'
		}
	];

	// Only `user` accounts own machines and tunnels — admin accounts never do.
	const specs: Record<string, MachineSpec[]> = {
		usr_sam: [
			{
				name: 'lab',
				hostname: 'sams-precision-5680',
				os: 'Linux (Ubuntu 24.04)',
				version: '0.4.2',
				online: true,
				verified: true,
				lastSeenMsAgo: 12_000,
				services: [
					{ name: 'grafana' },
					{ name: 'homeassistant' },
					{ name: 'immich' },
					{ name: 'sync' }
				]
			},
			{
				name: 'media',
				hostname: 'sams-macbook-pro',
				os: 'macOS 15.1',
				version: '0.4.2',
				online: true,
				verified: true,
				lastSeenMsAgo: 4_000,
				services: [{ name: 'jellyfin' }, { name: 'registry' }]
			},
			{
				name: 'attic',
				hostname: 'sams-thinkcentre',
				os: 'Linux (Debian 13)',
				version: '0.3.9',
				online: false,
				verified: false,
				lastSeenMsAgo: 60_000 * 60 * 5,
				services: [{ name: 'pihole', tunnel: 'closed' }, { name: 'n8n', tunnel: 'closed' }]
			}
		],
		usr_elena: [
			{
				name: 'workstation',
				hostname: 'elena-x1-carbon',
				os: 'Linux (Fedora 42)',
				version: '0.4.2',
				online: true,
				verified: true,
				lastSeenMsAgo: 6_000,
				services: [{ name: 'gitea' }, { name: 'paperless' }, { name: 'code' }]
			},
			{
				name: 'hub',
				hostname: 'elena-nuc-14',
				os: 'Linux (Ubuntu 24.04)',
				version: '0.4.2',
				online: true,
				verified: true,
				lastSeenMsAgo: 9_000,
				services: [
					{ name: 'vault', reputation: 98 },
					{ name: 'zigbee' },
					{ name: 'octoprint' }
				]
			}
		],
		usr_viktor: [
			{
				name: 'seedbox',
				hostname: 'viktor-ryzen-rig',
				os: 'Linux (Ubuntu 24.04)',
				version: '0.4.2',
				online: true,
				verified: false,
				lastSeenMsAgo: 8_000,
				services: [
					{ name: 'media', reputation: 26, flagged: true },
					{ name: 'immich', reputation: 34, flagged: true }
				]
			}
		],
		usr_dana: [
			{
				name: 'nas',
				hostname: 'dana-synology-ds920',
				os: 'Linux (DSM 7.2)',
				version: '0.3.7',
				online: false,
				verified: true,
				lastSeenMsAgo: 60_000 * 60 * 27,
				services: [{ name: 'media', reputation: 14, flagged: false, tunnel: 'suspended' }]
			}
		],
		usr_yuki: [
			{
				name: 'edge',
				hostname: 'yuki-hetzner-ax42',
				os: 'Linux (Ubuntu 24.04)',
				version: '0.4.1',
				online: true,
				verified: true,
				lastSeenMsAgo: 3_000,
				services: [
					{ name: 'media', reputation: 19, flagged: true },
					{ name: 'registry' },
					{ name: 'search', reputation: 44, flagged: true }
				]
			}
		],
		usr_omar: [
			{
				name: 'laptop',
				hostname: 'omar-xps-13',
				os: 'Linux (Arch)',
				version: '0.4.2',
				online: true,
				verified: false,
				lastSeenMsAgo: 60_000 * 48,
				services: [{ name: 'nextcloud' }, { name: 'code' }]
			},
			{
				name: 'lab',
				hostname: 'omar-mac-studio',
				os: 'macOS 15.1',
				version: '0.4.2',
				online: true,
				verified: true,
				lastSeenMsAgo: 15_000,
				services: [{ name: 'grafana' }, { name: 'n8n' }]
			}
		],
		usr_theo: [
			{
				name: 'desk',
				hostname: 'theo-framework',
				os: 'Linux (NixOS 25.05)',
				version: '0.4.0',
				online: true,
				verified: true,
				lastSeenMsAgo: 60_000 * 2,
				services: [{ name: 'search', reputation: 41, flagged: true }, { name: 'n8n' }]
			}
		],
		usr_clara: [
			{
				name: 'studio',
				hostname: 'clara-mac-mini',
				os: 'macOS 15.0',
				version: '0.4.2',
				online: true,
				verified: true,
				lastSeenMsAgo: 60_000 * 3,
				services: [{ name: 'paperless' }, { name: 'immich' }]
			}
		],
		usr_maya: [
			{
				name: 'relaybox',
				hostname: 'maya-talos-node1',
				os: 'Linux (Ubuntu 24.04)',
				version: '0.4.2',
				online: true,
				verified: true,
				lastSeenMsAgo: 5_000,
				services: [{ name: 'grafana' }, { name: 'gitea' }, { name: 'vault' }]
			}
		],
		usr_devon: [
			{
				name: 'field',
				hostname: 'devon-rpi5-kit',
				os: 'Linux (Debian 13)',
				version: '0.4.1',
				online: false,
				verified: true,
				lastSeenMsAgo: 60_000 * 60 * 3,
				services: [{ name: 'homeassistant', tunnel: 'closed' }, { name: 'zigbee', tunnel: 'closed' }]
			}
		],
		usr_pavel: [
			{
				name: 'ops',
				hostname: 'pavel-dell-r740',
				os: 'Linux (Rocky 9)',
				version: '0.3.6',
				online: false,
				verified: true,
				lastSeenMsAgo: 60_000 * 60 * 9,
				services: [
					{ name: 'media', reputation: 12, flagged: true, tunnel: 'suspended' },
					{ name: 'registry', tunnel: 'suspended' }
				]
			}
		]
	};

	let seedCounter = 7;
	const machines: Machine[] = [];
	for (const person of people) {
		const personSpecs = specs[person.id] ?? [];
		for (const spec of personSpecs) {
			seedCounter += 13;
			machines.push(buildMachine(person.id, person.slug, spec, seedCounter));
		}
	}

	const review = buildReview(machines, people);
	return { orgs, people, machines, review };
}

// ---- review queue ---------------------------------------------------------

const REVIEW_REASONS: Record<string, string> = {
	media: 'Sustained bulk transfer to blocklisted mirror hosts; payload hashes match known infringing catalogue.',
	immich: 'Perceptual hash classifier matched flagged visual material in public album shares.',
	search: 'Query strings matching an automated probing pattern against known credential dumps.',
	registry: 'Anonymous blob pulls well above the org baseline for this hour.'
};

function makeEvidenceSvg(infraction: string, path: string, seed: number): string {
	const hue = (seed * 53) % 360;
	const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 420 220" width="420" height="220">
		<defs>
			<pattern id="g${seed}" width="18" height="18" patternUnits="userSpaceOnUse">
				<rect width="9" height="9" fill="hsl(${hue} 22% 16%)"/>
				<rect x="9" width="9" height="9" fill="hsl(${hue} 18% 12%)"/>
				<rect y="9" width="9" height="9" fill="hsl(${hue} 18% 12%)"/>
				<rect x="9" y="9" width="9" height="9" fill="hsl(${hue} 22% 16%)"/>
			</pattern>
		</defs>
		<rect width="420" height="220" fill="url(#g${seed})"/>
		<rect x="34" y="28" width="160" height="118" fill="hsl(${hue} 28% 24%)" opacity="0.7"/>
		<circle cx="290" cy="96" r="54" fill="hsl(${(hue + 40) % 360} 32% 28%)" opacity="0.65"/>
		<rect x="20" y="160" width="380" height="40" fill="#0b0604" opacity="0.88" stroke="#a44039" stroke-width="1.5"/>
		<text x="32" y="178" fill="#ffb8af" font-family="monospace" font-size="11" font-weight="700">REDACTED SAMPLE · ${infraction}</text>
		<text x="32" y="193" fill="#cdc6bf" font-family="monospace" font-size="10">${path}</text>
	</svg>`;
	return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

const SAMPLE_TEMPLATES: {
	method: string;
	path: string;
	contentType: string;
	infraction: string;
	isImage: boolean;
}[] = [
	{
		method: 'GET',
		path: '/media/albums/shared/img_9941a.jpg',
		contentType: 'image/jpeg',
		infraction: 'CSAM · PDQ perceptual hash (99.4%)',
		isImage: true
	},
	{
		method: 'GET',
		path: '/api/assets/fe09-c41a/thumbnail.webp',
		contentType: 'image/webp',
		infraction: 'CSAM · PhotoDNA signature match',
		isImage: true
	},
	{
		method: 'POST',
		path: '/auth/verify-sso/collect',
		contentType: 'text/html',
		infraction: 'Phishing · credential harvest kit',
		isImage: false
	},
	{
		method: 'GET',
		path: '/dist/stage2/loader_linux_amd64.bin',
		contentType: 'application/octet-stream',
		infraction: 'Malware · staged ELF dropper',
		isImage: false
	},
	{
		method: 'GET',
		path: '/media/cache/preview_0082.png',
		contentType: 'image/png',
		infraction: 'Non-consensual intimate imagery hash',
		isImage: true
	},
	{
		method: 'POST',
		path: '/v2/beacon/checkin',
		contentType: 'application/json',
		infraction: 'Botnet · C2 beacon check-in',
		isImage: false
	}
];

function buildReview(machines: Machine[], people: Person[]): ReviewItem[] {
	const r = rng(5150);
	const items: ReviewItem[] = [];
	for (const machine of machines) {
		const person = people.find((p) => p.id === machine.personId);
		if (!person || person.status === 'suspended') {
			continue;
		}
		for (const service of machine.services) {
			if (!service.flagged) {
				continue;
			}
			const sample: LogEntry[] = [];
			for (let i = 0; i < 6; i += 1) {
				const tpl = SAMPLE_TEMPLATES[(i + service.name.length) % SAMPLE_TEMPLATES.length];
				const log = makeLog(service, machine);
				log.method = tpl.method;
				log.path = tpl.path;
				log.contentType = tpl.contentType;
				log.flagged = true;
				log.infraction = tpl.infraction;
				log.imagePreview = tpl.isImage
					? makeEvidenceSvg(tpl.infraction, tpl.path, i * 17 + service.reputation)
					: '';
				log.reputation = Math.max(5, service.reputation - i * 3);
				sample.push(log);
			}
			items.push({
				id: nextId('rev'),
				serviceId: service.id,
				machineId: machine.id,
				personId: person.id,
				orgId: person.orgId,
				score: service.reputation,
				threshold: 50,
				reason: REVIEW_REASONS[service.name] ?? 'The ranker attached a low score to this service.',
				distinctFingerprints: Math.round(48 + r() * 290),
				infractions: [
					{
						category: 'CSAM · perceptual hash match',
						count: Math.round(2 + r() * 9),
						severity: 'critical'
					},
					{
						category: 'Malware · staged dropper payload',
						count: Math.round(4 + r() * 18),
						severity: 'high'
					},
					{
						category: 'Phishing · credential harvest kit',
						count: Math.round(3 + r() * 14),
						severity: 'high'
					},
					{
						category: 'Botnet · C2 beacon traffic',
						count: Math.round(1 + r() * 11),
						severity: 'medium'
					}
				],
				sample,
				createdAt: iso(MINUTE * Math.round(20 + r() * 600)),
				verdict: 'pending'
			});
		}
	}
	return items;
}

// ---- live log generation --------------------------------------------------

const METHODS = ['GET', 'GET', 'GET', 'POST', 'PUT', 'DELETE', 'HEAD'];
const REGIONS = ['fra1', 'ams3', 'cdg1', 'lhr2', 'iad1', 'sfo3'];
const UAS = [
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/131.0',
	'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0',
	'curl/8.7.1',
	'Immich-Android/1.118.0',
	'HomeAssistant/2024.11 (iOS 18.1)',
	'Jellyfin-Media-Player/10.10.3',
	'okhttp/4.12.0',
	'python-requests/2.32.3'
];
const R = rng(20261019);

function pick<T>(arr: T[]): T {
	return arr[Math.floor(R() * arr.length)];
}

function statusFor(errorRate: number): number {
	const roll = R();
	if (roll < errorRate * 0.35) {
		return pick([500, 502, 503]);
	}
	if (roll < errorRate) {
		return pick([400, 401, 403, 404, 429]);
	}
	if (roll < errorRate + 0.05) {
		return pick([301, 302, 304]);
	}
	return pick([200, 200, 200, 200, 204, 206]);
}

/** Builds one plausible request against a service. */
export function makeLog(service: Service, machine: Machine): LogEntry {
	const entry = catalog(service.name);
	const status = statusFor(service.errorRate);
	const method = pick(METHODS);
	const path = pick(entry.paths);
	const bytesOut = Math.round(entry.bigness * (200 + R() * 3000));
	const bytesIn = method === 'POST' || method === 'PUT' ? Math.round(200 + R() * 8000) : Math.round(R() * 400);
	const flagged = service.flagged && R() > 0.4;
	const reputation = flagged
		? Math.round(service.reputation * (0.5 + R() * 0.5))
		: Math.round(78 + R() * 22);
	const ua = pick(UAS);

	const contentType = path.endsWith('.js')
		? 'application/javascript'
		: path.endsWith('.css')
			? 'text/css'
			: path.endsWith('.html')
				? 'text/html'
				: entry.contentType;

	let responseBody = '';
	if (status >= 400) {
		responseBody = JSON.stringify(
			{
				error: status >= 500 ? 'upstream_origin_error' : 'not_found',
				status,
				path,
				requestId: nextId('req')
			},
			null,
			2
		);
	} else if (contentType === 'text/html') {
		responseBody = `<!doctype html>\n<html lang="en">\n  <head>\n    <meta charset="utf-8" />\n    <title>${service.name} · ${service.hostname}</title>\n    <link rel="stylesheet" href="/static/app.css" />\n  </head>\n  <body class="shell" data-service="${service.name}">\n    <main id="app">Ready.</main>\n  </body>\n</html>`;
	} else if (contentType === 'application/javascript') {
		responseBody = `// ${service.name} bundle chunk\nexport async function bootstrap(config) {\n  const res = await fetch("${path}", { credentials: "same-origin" });\n  const data = await res.json();\n  return { ok: res.ok, version: "${machine.agentVersion}", items: data.items };\n}`;
	} else if (contentType === 'text/css') {
		responseBody = `:root {\n  --surface: #0b0604;\n  --accent: #ffcf2e;\n}\n.shell {\n  display: grid;\n  background: var(--surface);\n  color: var(--accent);\n}`;
	} else {
		responseBody = JSON.stringify(
			{
				ok: true,
				service: service.name,
				host: service.hostname,
				items: Math.round(R() * 40),
				latencyMs: Math.round(4 + R() * 90),
				cached: R() > 0.5
			},
			null,
			2
		);
	}

	return {
		id: nextId('log'),
		ts: Date.now(),
		machineId: machine.id,
		serviceId: service.id,
		method,
		path,
		status,
		bytesOut,
		bytesIn,
		durationMs: Math.round(3 + R() * 260),
		clientIp: `${pick([51, 62, 84, 91, 145, 185])}.${Math.floor(R() * 255)}.${Math.floor(R() * 255)}.${Math.floor(R() * 255)}`,
		region: pick(REGIONS),
		userAgent: ua,
		contentType,
		reputation,
		flagged,
		infraction: '',
		imagePreview: '',
		requestHeaders: [
			['host', service.hostname],
			['user-agent', ua],
			['accept', R() > 0.5 ? 'application/json' : '*/*'],
			['accept-encoding', 'gzip, br, zstd'],
			['x-forwarded-for', `${Math.floor(R() * 255)}.${Math.floor(R() * 255)}.${Math.floor(R() * 255)}.${Math.floor(R() * 255)}`]
		],
		responseHeaders: [
			['content-type', contentType],
			['content-encoding', R() > 0.4 ? 'zstd' : 'identity'],
			['cache-control', R() > 0.7 ? 'no-store' : 'public, max-age=60'],
			['x-weaver-region', pick(REGIONS)],
			['server', service.name]
		],
		requestBody:
			method === 'POST' || method === 'PUT'
				? JSON.stringify({ query: path, ts: Date.now(), payload: { count: Math.round(R() * 12) } }, null, 2)
				: '',
		responseBody,
		onTheWire: Math.round((bytesOut + bytesIn) * (R() > 0.4 ? 0.42 : 0.61))
	};
}
