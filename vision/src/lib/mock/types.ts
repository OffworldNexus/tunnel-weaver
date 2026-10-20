/**
 * The domain model the console renders.
 *
 * This is a vision mock: the shapes are the ones we want the relay to serve
 * one day, but every value comes from `data.ts` and mutates only in memory.
 * Strings are never nullable — an empty string means "no value" (AGENTS.md).
 */

export type Role = 'user' | 'org_admin' | 'super_admin';

export type Health = 'online' | 'idle' | 'offline';

export type AccountStatus = 'active' | 'suspended' | 'invited';

export type OrgStatus = 'active' | 'suspended';

export type TunnelState = 'open' | 'closed' | 'suspended';

/** A review verdict on a flagged service, decided by a human or the ranker. */
export type Verdict = 'pending' | 'cleared' | 'banned';

export interface Org {
	id: string;
	name: string;
	/** The org slug; also the prefix of every member's person slug. */
	slug: string;
	status: OrgStatus;
	createdAt: string;
	/** Support mailbox for the org, or empty. */
	contactEmail: string;
	/** 0–100; how quickly and responsibly the org handles suspicious users. */
	reputation: number;
	/** Median time (in minutes) the org takes to act on a flagged user. */
	meanResponseMinutes: number;
	/** Admin annotation recorded when the org was banned, or empty. */
	banReason: string;
	/** ISO timestamp of when the org was banned, or empty. */
	bannedAt: string;
	/** Non-content proof summary retained after raw samples are purged, or empty. */
	bannedSummary: string;
}

export interface Person {
	id: string;
	orgId: string;
	name: string;
	email: string;
	/** `<person>` in `<person>-<machine>-<service>.<root>`. */
	slug: string;
	role: Role;
	status: AccountStatus;
	createdAt: string;
	/** ISO timestamp of the last authenticated request, or empty. */
	lastSeenAt: string;
	/** 0–100; the person's aggregated service reputation. */
	reputation: number;
	/** Marks the person whose account is signed in during a demo. */
	demo: boolean;
	/** Admin annotation recorded when the user was banned, or empty. */
	banReason: string;
	/** ISO timestamp of when the user was banned, or empty. */
	bannedAt: string;
	/** Non-content proof summary retained after raw samples are purged, or empty. */
	bannedSummary: string;
}

export interface Service {
	id: string;
	machineId: string;
	/** `<service>` label, `[a-z0-9]{1,15}`. */
	name: string;
	/** Fully-qualified public hostname. */
	hostname: string;
	/** The local origin the weaver proxies to, e.g. `http://127.0.0.1:8080`. */
	target: string;
	tunnel: TunnelState;
	/** Bytes/sec shape over the last hour, sampled every 5 minutes. */
	reputation: number;
	flagged: boolean;
	verdict: Verdict;
	/** Cumulative counters since the tunnel opened. */
	requests: number;
	bytesIn: number;
	bytesOut: number;
	/** Requests in the last hour. */
	requestsHour: number;
	errorRate: number;
	avgLatencyMs: number;
	openedAt: string;
	/** Minute-by-minute traffic for the last hour (60 samples). */
	series: TrafficPoint[];
	/** HTTP status-class breakdown over the last hour. */
	codeClasses: CodeClass[];
	/** The most common paths, for the detail panel. */
	topPaths: PathStat[];
}

export interface Machine {
	id: string;
	personId: string;
	/** `<machine>` label; unique per person. */
	name: string;
	/** The raw hostname the CLI reported. */
	hostname: string;
	fingerprint: string;
	os: string;
	agentVersion: string;
	online: boolean;
	pairedAt: string;
	lastSeenAt: string;
	/** Whether the person has confirmed the fingerprint out of band. */
	verified: boolean;
	services: Service[];
	/** Minute-by-minute traffic aggregated across the machine's services. */
	series: TrafficPoint[];
}

export interface TrafficPoint {
	/** Epoch millis. */
	ts: number;
	/**
	 * Public-edge (external) bytes: what crossed the relay's internet-facing side.
	 * `In` is uploaded by the client, `Out` is relayed back to it.
	 */
	bytesIn: number;
	bytesOut: number;
	/** The mux leg to the machine — the same traffic, on the wire (compressed). */
	tunIn: number;
	tunOut: number;
	requests: number;
}

export interface CodeClass {
	/** `2xx`, `3xx`, `4xx`, `5xx`. */
	label: string;
	count: number;
}

export interface PathStat {
	path: string;
	count: number;
	/** Mean latency in milliseconds. */
	avgMs: number;
}

export interface LogEntry {
	id: string;
	ts: number;
	machineId: string;
	serviceId: string;
	method: string;
	path: string;
	status: number;
	/** Bytes relayed to the client. */
	bytesOut: number;
	/** Bytes uploaded by the client. */
	bytesIn: number;
	durationMs: number;
	clientIp: string;
	region: string;
	userAgent: string;
	contentType: string;
	/** 0–100 internal score; not shown on normal live queries. */
	reputation: number;
	/** Whether the ranker flagged this query for human review. */
	flagged: boolean;
	/** Infraction label when this query is part of a sampled offense, or empty. */
	infraction: string;
	/** Data-URI preview when the sampled query is an image, or empty. */
	imagePreview: string;
	// ---- inspection mode ----
	requestHeaders: [string, string][];
	responseHeaders: [string, string][];
	requestBody: string;
	responseBody: string;
	/** On-the-wire compressed size on the mux tunnel, in bytes. */
	onTheWire: number;
}

export interface InfractionCount {
	category: string;
	count: number;
	severity: 'critical' | 'high' | 'medium';
}

/** One row in the abuse review queue. */
export interface ReviewItem {
	id: string;
	serviceId: string;
	machineId: string;
	personId: string;
	orgId: string;
	/** The score that tripped the threshold. */
	score: number;
	threshold: number;
	reason: string;
	/** Number of distinct visitor fingerprints seen across this user's tunnels. */
	distinctFingerprints: number;
	/** Breakdown of detected infractions by category. */
	infractions: InfractionCount[];
	/** A representative sample of the flagged queries (including images). */
	sample: LogEntry[];
	createdAt: string;
	verdict: Verdict;
}

export interface Session {
	/** The signed-in person. */
	personId: string;
	/**
	 * The scope the console is operating in: their own account, an org they
	 * administer, or the whole fleet.
	 */
	role: Role;
}

/** A person the current viewer is allowed to open; used by the drill-down pages. */
export interface Viewer {
	person: Person;
	role: Role;
	/** The org being administered, when `role` is `org_admin`. */
	orgId: string;
}
