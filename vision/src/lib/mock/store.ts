/**
 * The single mutable copy of the mock world.
 *
 * Everything the console shows reads from these stores; every action the
 * console offers writes through the mutators here. A `setInterval` ticker
 * keeps the streams and counters moving so the app feels live.
 */
import { derived, get, writable, type Readable, type Writable } from 'svelte/store';

import { buildSeed, makeLog, nextId, ROOT } from './data';
import type {
	AccountStatus,
	Health,
	LogEntry,
	Machine,
	Org,
	Person,
	ReviewItem,
	Role,
	Service,
	Session,
	Verdict
} from './types';

const seed = buildSeed();

const SESSION_KEY = 'tw-vision-session';

function initialSession(): Session | null {
	if (typeof localStorage === 'undefined') {
		return null;
	}
	try {
		const raw = localStorage.getItem(SESSION_KEY);
		return raw ? (JSON.parse(raw) as Session) : null;
	} catch {
		return null;
	}
}

export const orgs: Writable<Org[]> = writable(seed.orgs);
export const people: Writable<Person[]> = writable(seed.people);
export const machines: Writable<Machine[]> = writable(seed.machines);
export const review: Writable<ReviewItem[]> = writable(seed.review);
/** Transient HTTP query buffer — only populated while `capturingLogs` is true. */
export const logs: Writable<LogEntry[]> = writable([]);
export const capturingLogs: Writable<boolean> = writable(false);
export const session: Writable<Session | null> = writable(initialSession());
/** The log entry currently open in inspection mode, or null. */
export const inspecting: Writable<LogEntry | null> = writable(null);
/** Whether the live streams keep producing new data. */
export const live: Writable<boolean> = writable(true);

// Keep the chosen persona across reloads so the preview stays put.
session.subscribe((value) => {
	if (typeof localStorage === 'undefined') {
		return;
	}
	try {
		if (value) {
			localStorage.setItem(SESSION_KEY, JSON.stringify(value));
		} else {
			localStorage.removeItem(SESSION_KEY);
		}
	} catch {
		// Private mode: the session still applies for this tab.
	}
});

const LOG_CAP = 400;

export function startLogCapture(machineId?: string): void {
	capturingLogs.set(true);
	const currentLogs = get(logs);
	if (currentLogs.length === 0) {
		const burst: LogEntry[] = [];
		const targetMachines = get(machines).filter(
			(m) => m.online && (!machineId || m.id === machineId)
		);
		for (const machine of targetMachines) {
			for (const service of machine.services) {
				if (service.tunnel !== 'open') {
					continue;
				}
				for (let i = 0; i < 4; i += 1) {
					const l = makeLog(service, machine);
					l.ts = Date.now() - (4 - i) * 1200;
					burst.push(l);
				}
			}
		}
		logs.set(burst.sort((a, b) => b.ts - a.ts));
	}
}

export function stopLogCapture(): void {
	capturingLogs.set(false);
}

export function clearCapturedLogs(): void {
	logs.set([]);
}

// ---- lookups --------------------------------------------------------------

export function personById(id: string): Person | undefined {
	return get(people).find((p) => p.id === id);
}

export function orgById(id: string): Org | undefined {
	return get(orgs).find((o) => o.id === id);
}

export function machineById(id: string): Machine | undefined {
	return get(machines).find((m) => m.id === id);
}

export function personOfMachine(machine: Machine): Person | undefined {
	return get(people).find((p) => p.id === machine.personId);
}

export function orgOfPerson(person: Person): Org | undefined {
	return get(orgs).find((o) => o.id === person.orgId);
}

export function orgOfMachine(machine: Machine): Org | undefined {
	const person = personOfMachine(machine);
	return person ? orgOfPerson(person) : undefined;
}

export function allServices(list: Machine[] = get(machines)): { service: Service; machine: Machine }[] {
	return list.flatMap((machine) => machine.services.map((service) => ({ service, machine })));
}

export function serviceById(id: string): { service: Service; machine: Machine } | undefined {
	return allServices().find((s) => s.service.id === id);
}

export function healthOf(machine: Machine): Health {
	if (!machine.online) {
		return 'offline';
	}
	const idle = Date.now() - new Date(machine.lastSeenAt).getTime() > 90_000;
	return idle ? 'idle' : 'online';
}

export function tunnelHealth(service: Service, machine: Machine): Health {
	if (service.tunnel === 'suspended') {
		return 'offline';
	}
	if (service.tunnel === 'closed') {
		return 'offline';
	}
	return healthOf(machine);
}

// ---- session & drill-down selection ---------------------------------------

export interface Current {
	person: Person;
	/** The viewer's own organisation, or null for the global super admin. */
	org: Org | null;
	role: Role;
}

const SEL_ORG_KEY = 'tw-vision-sel-org';
const SEL_PERSON_KEY = 'tw-vision-sel-person';

function initialStored(key: string): string {
	if (typeof sessionStorage === 'undefined') {
		return '';
	}
	try {
		return sessionStorage.getItem(key) ?? '';
	} catch {
		return '';
	}
}

/** The organisation currently selected in the sidebar drill-down (super admin). */
export const selectedOrgId: Writable<string> = writable(initialStored(SEL_ORG_KEY));
/** The user currently selected in the sidebar drill-down (org/super admin). */
export const selectedPersonId: Writable<string> = writable(initialStored(SEL_PERSON_KEY));

selectedOrgId.subscribe((value) => {
	if (typeof sessionStorage === 'undefined') {
		return;
	}
	try {
		if (value) {
			sessionStorage.setItem(SEL_ORG_KEY, value);
		} else {
			sessionStorage.removeItem(SEL_ORG_KEY);
		}
	} catch {
		// ignore
	}
});

selectedPersonId.subscribe((value) => {
	if (typeof sessionStorage === 'undefined') {
		return;
	}
	try {
		if (value) {
			sessionStorage.setItem(SEL_PERSON_KEY, value);
		} else {
			sessionStorage.removeItem(SEL_PERSON_KEY);
		}
	} catch {
		// ignore
	}
});

export function selectOrg(orgId: string): void {
	selectedOrgId.set(orgId);
	selectedPersonId.set('');
}

export function selectPerson(personId: string): void {
	const person = personById(personId);
	if (person?.orgId) {
		selectedOrgId.set(person.orgId);
	}
	selectedPersonId.set(personId);
}

export function clearSelection(): void {
	selectedOrgId.set('');
	selectedPersonId.set('');
}

export const current: Readable<Current | null> = derived(
	[session, people, orgs],
	([$session, $people, $orgs]) => {
		if (!$session) {
			return null;
		}
		const person = $people.find((p) => p.id === $session.personId);
		if (!person) {
			return null;
		}
		const org = person.orgId ? ($orgs.find((o) => o.id === person.orgId) ?? null) : null;
		if ($session.role !== 'super_admin' && !org) {
			return null;
		}
		return { person, org, role: $session.role };
	}
);

/**
 * The organisation in scope right now: for an org admin (or user), their own
 * org; for a super admin, whichever org is currently selected in the tree.
 */
export const activeOrg: Readable<Org | null> = derived(
	[current, orgs, selectedOrgId],
	([$current, $orgs, $selectedOrgId]) => {
		if (!$current) {
			return null;
		}
		if ($current.role === 'super_admin') {
			return $selectedOrgId ? ($orgs.find((o) => o.id === $selectedOrgId) ?? null) : null;
		}
		return $current.org;
	}
);

/**
 * The user in scope right now: for a regular user, themselves; for an org or
 * super admin, whichever user they drilled into.
 */
export const activePerson: Readable<Person | null> = derived(
	[current, people, selectedPersonId],
	([$current, $people, $selectedPersonId]) => {
		if (!$current) {
			return null;
		}
		if ($current.role === 'user') {
			return $current.person;
		}
		return $selectedPersonId ? ($people.find((p) => p.id === $selectedPersonId) ?? null) : null;
	}
);

/** Signs in as a person, adopting the role the demo intends. */
export function signIn(personId: string, role?: Role): void {
	const person = personById(personId);
	if (!person) {
		return;
	}
	clearSelection();
	session.set({ personId, role: role ?? person.role });
}

export function signOut(): void {
	clearSelection();
	session.set(null);
}

/**
 * The set of people the current viewer may open. A user sees only themselves; an
 * org admin sees their org's users; a super admin sees everyone.
 */
export const visiblePeople: Readable<Person[]> = derived(
	[current, activeOrg, people],
	([$current, $activeOrg, $people]) => {
		if (!$current) {
			return [];
		}
		if ($current.role === 'super_admin') {
			return $people.filter((p) => p.role !== 'super_admin');
		}
		if ($current.role === 'org_admin') {
			return $people.filter((p) => p.orgId === $activeOrg?.id && p.role === 'user');
		}
		return $people.filter((p) => p.id === $current.person.id);
	}
);

export const visibleOrgs: Readable<Org[]> = derived([current, orgs], ([$current, $orgs]) => {
	if (!$current) {
		return [];
	}
	return $current.role === 'super_admin' ? $orgs : $orgs.filter((o) => o.id === $current.org?.id);
});

export const visibleMachines: Readable<Machine[]> = derived(
	[current, activeOrg, activePerson, machines, people],
	([$current, $activeOrg, $activePerson, $machines, $people]) => {
		if (!$current) {
			return [];
		}
		if ($activePerson) {
			return $machines.filter((m) => m.personId === $activePerson.id);
		}
		if ($activeOrg) {
			const ids = new Set($people.filter((p) => p.orgId === $activeOrg.id).map((p) => p.id));
			return $machines.filter((m) => ids.has(m.personId));
		}
		if ($current.role === 'super_admin') {
			return $machines;
		}
		return $machines.filter((m) => m.personId === $current.person.id);
	}
);

export const visibleReview: Readable<ReviewItem[]> = derived(
	[current, activeOrg, review],
	([$current, $activeOrg, $review]) => {
		if (!$current) {
			return [];
		}
		if ($current.role === 'super_admin') {
			return $activeOrg ? $review.filter((r) => r.orgId === $activeOrg.id) : $review;
		}
		if ($current.role === 'org_admin') {
			return $review.filter((r) => r.orgId === $activeOrg?.id);
		}
		return [];
	}
);

// ---- mutations ------------------------------------------------------------

export function renameMachine(machineId: string, name: string): void {
	machines.update((list) =>
		list.map((machine) => {
			if (machine.id !== machineId) {
				return machine;
			}
			const person = get(people).find((p) => p.id === machine.personId);
			const slug = person?.slug ?? 'person';
			return {
				...machine,
				name,
				services: machine.services.map((s) => ({
					...s,
					hostname: `${slug}-${name}-${s.name}.${ROOT}`
				}))
			};
		})
	);
}

export function unpairMachine(machineId: string): void {
	machines.update((list) => list.filter((m) => m.id !== machineId));
	review.update((list) => list.filter((r) => r.machineId !== machineId));
}

export function verifyMachine(machineId: string): void {
	machines.update((list) => list.map((m) => (m.id === machineId ? { ...m, verified: true } : m)));
}

/**
 * One-way disconnect from the web UI: drops the machine's live mux connection
 * and closes its open service tunnels. Reconnecting requires the user to run
 * `weave start` on the machine itself.
 */
export function kickMachine(machineId: string): void {
	const nowIso = new Date().toISOString();
	machines.update((list) =>
		list.map((m) =>
			m.id === machineId
				? {
						...m,
						online: false,
						lastSeenAt: nowIso,
						services: m.services.map((s) =>
							s.tunnel === 'open' ? { ...s, tunnel: 'closed' as const } : s
						)
					}
				: m
		)
	);
}

export function setTunnel(serviceId: string, tunnel: Service['tunnel']): void {
	machines.update((list) =>
		list.map((m) => ({
			...m,
			services: m.services.map((s) =>
				s.id === serviceId
					? { ...s, tunnel, openedAt: tunnel === 'open' ? new Date().toISOString() : s.openedAt }
					: s
			)
		}))
	);
}

export function suspendPerson(personId: string): void {
	people.update((list) =>
		list.map((p) => (p.id === personId ? { ...p, status: 'suspended' as AccountStatus } : p))
	);
	// Suspension freezes every tunnel the person owns, immediately.
	machines.update((list) =>
		list.map((m) =>
			m.personId === personId
				? {
						...m,
						services: m.services.map((s) =>
							s.tunnel === 'open' ? { ...s, tunnel: 'suspended' as const } : s
						)
					}
				: m
		)
	);
}

export function reinstatePerson(personId: string): void {
	people.update((list) =>
		list.map((p) =>
			p.id === personId
				? {
						...p,
						status: 'active' as AccountStatus,
						banReason: '',
						bannedAt: '',
						bannedSummary: '',
						reputation: Math.max(85, p.reputation)
					}
				: p
		)
	);
	machines.update((list) =>
		list.map((m) =>
			m.personId === personId
				? {
						...m,
						services: m.services.map((s) =>
							s.tunnel === 'suspended' ? { ...s, tunnel: 'closed' as const } : s
						)
					}
				: m
		)
	);
}

/**
 * Clears a user of bad behaviour: deletes all suspicion/review items for that
 * user, clears `flagged` on their services, and recomputes both the user's and
 * their organisation's reputation scores.
 */
export function clearPersonOffenses(personId: string): void {
	const person = personById(personId);
	review.update((list) => list.filter((r) => r.personId !== personId));
	machines.update((list) =>
		list.map((m) =>
			m.personId === personId
				? {
						...m,
						services: m.services.map((s) => ({
							...s,
							flagged: false,
							verdict: 'cleared' as const,
							reputation: Math.max(94, s.reputation)
						}))
					}
				: m
		)
	);
	people.update((list) =>
		list.map((p) => (p.id === personId ? { ...p, reputation: 96 } : p))
	);
	if (person?.orgId) {
		recomputeOrgReputation(person.orgId);
	}
}

/**
 * Bans a user with an admin annotation: stores the annotation and non-content
 * proof summary on the user record, purges the raw offending samples so
 * criminal material is not kept forever, freezes all of their tunnels, and
 * recomputes the organisation's score.
 */
export function banPersonWithNote(personId: string, note: string): void {
	const person = personById(personId);
	const items = get(review).filter((r) => r.personId === personId);
	const fingerprints = items.reduce((a, r) => a + r.distinctFingerprints, 0);
	const tallies = new Map<string, number>();
	for (const item of items) {
		for (const inf of item.infractions) {
			tallies.set(inf.category, (tallies.get(inf.category) ?? 0) + inf.count);
		}
	}
	const infSummary = [...tallies.entries()]
		.slice(0, 3)
		.map(([k, v]) => `${k} (${v})`)
		.join(', ');
	const summary = items.length
		? `${fingerprints} distinct visitor fingerprints · ${infSummary} · Raw samples purged at ban.`
		: 'Manual administrative suspension · All tunnels frozen.';

	people.update((list) =>
		list.map((p) =>
			p.id === personId
				? {
						...p,
						status: 'suspended' as AccountStatus,
						reputation: Math.min(p.reputation, 15),
						banReason: note.trim() || 'Suspended by administrator after abuse review.',
						bannedAt: new Date().toISOString(),
						bannedSummary: summary
					}
				: p
		)
	);
	machines.update((list) =>
		list.map((m) =>
			m.personId === personId
				? {
						...m,
						online: false,
						services: m.services.map((s) => ({
							...s,
							flagged: false,
							verdict: 'banned' as const,
							tunnel: 'suspended' as const
						}))
					}
				: m
		)
	);
	// Purge the raw offending samples now that the ban & summary are recorded.
	review.update((list) => list.filter((r) => r.personId !== personId));
	if (person?.orgId) {
		recomputeOrgReputation(person.orgId);
	}
}

function recomputeOrgReputation(orgId: string): void {
	const orgUsers = get(people).filter((p) => p.orgId === orgId && p.role === 'user');
	const activeUsers = orgUsers.filter((p) => p.status === 'active');
	const pendingCount = get(review).filter(
		(r) => r.orgId === orgId && r.verdict === 'pending'
	).length;
	const meanUserRep = activeUsers.length
		? activeUsers.reduce((a, u) => a + u.reputation, 0) / activeUsers.length
		: 92;
	const nextScore = Math.max(15, Math.min(99, Math.round(meanUserRep - pendingCount * 12)));
	orgs.update((list) =>
		list.map((o) => (o.id === orgId ? { ...o, reputation: nextScore } : o))
	);
}

export function updatePerson(personId: string, patch: Partial<Person>): void {
	people.update((list) => list.map((p) => (p.id === personId ? { ...p, ...patch } : p)));
}

export function createPerson(input: {
	orgId: string;
	name: string;
	email: string;
	slug: string;
	role: Role;
}): Person {
	const person: Person = {
		id: nextId('usr'),
		orgId: input.orgId,
		name: input.name,
		email: input.email,
		slug: input.slug,
		role: input.role,
		status: 'invited',
		createdAt: new Date().toISOString(),
		lastSeenAt: '',
		reputation: 100,
		demo: false,
		banReason: '',
		bannedAt: '',
		bannedSummary: ''
	};
	people.update((list) => [...list, person]);
	return person;
}

export function deletePerson(personId: string): void {
	people.update((list) => list.filter((p) => p.id !== personId));
	machines.update((list) => list.filter((m) => m.personId !== personId));
}

export function createOrg(input: { name: string; slug: string; contactEmail?: string }): Org {
	const org: Org = {
		id: nextId('org'),
		name: input.name,
		slug: input.slug,
		status: 'active',
		createdAt: new Date().toISOString(),
		contactEmail: input.contactEmail ?? '',
		reputation: 100,
		meanResponseMinutes: 15,
		banReason: '',
		bannedAt: '',
		bannedSummary: ''
	};
	orgs.update((list) => [...list, org]);
	return org;
}

export function updateOrg(orgId: string, patch: Partial<Org>): void {
	orgs.update((list) => list.map((o) => (o.id === orgId ? { ...o, ...patch } : o)));
}

export function suspendOrg(orgId: string, note?: string): void {
	const org = orgById(orgId);
	const items = get(review).filter((r) => r.orgId === orgId);
	const fingerprints = items.reduce((a, r) => a + r.distinctFingerprints, 0);
	const summary = items.length
		? `Score at ban: ${org?.reputation ?? 0}/100 · Median response: ${org?.meanResponseMinutes ?? 0}m · ${fingerprints} visitor fingerprints across ${items.length} flagged service(s) · Raw samples purged at ban.`
		: `Score at ban: ${org?.reputation ?? 0}/100 · Administrative suspension · All member tunnels frozen.`;

	orgs.update((list) =>
		list.map((o) =>
			o.id === orgId
				? {
						...o,
						status: 'suspended' as const,
						banReason:
							note?.trim() ||
							o.banReason ||
							'Suspended by super admin for unresolved abuse across member tunnels.',
						bannedAt: new Date().toISOString(),
						bannedSummary: summary
					}
				: o
		)
	);
	// A suspended org takes every member's tunnels down with it and purges raw samples.
	people.update((list) =>
		list.map((p) => (p.orgId === orgId ? { ...p, status: 'suspended' as AccountStatus } : p))
	);
	const memberIds = new Set(get(people).filter((p) => p.orgId === orgId).map((p) => p.id));
	machines.update((list) =>
		list.map((m) =>
			memberIds.has(m.personId)
				? {
						...m,
						online: false,
						services: m.services.map((s) =>
							s.tunnel === 'open' ? { ...s, tunnel: 'suspended' as const } : s
						)
					}
				: m
		)
	);
	review.update((list) => list.filter((r) => r.orgId !== orgId));
}

export function reinstateOrg(orgId: string): void {
	orgs.update((list) =>
		list.map((o) =>
			o.id === orgId
				? {
						...o,
						status: 'active' as const,
						banReason: '',
						bannedAt: '',
						bannedSummary: ''
					}
				: o
		)
	);
	people.update((list) =>
		list.map((p) => (p.orgId === orgId ? { ...p, status: 'active' as AccountStatus } : p))
	);
	const memberIds = new Set(get(people).filter((p) => p.orgId === orgId).map((p) => p.id));
	machines.update((list) =>
		list.map((m) =>
			memberIds.has(m.personId)
				? {
						...m,
						services: m.services.map((s) =>
							s.tunnel === 'suspended' ? { ...s, tunnel: 'closed' as const } : s
						)
					}
				: m
		)
	);
}

export function deleteOrg(orgId: string): void {
	const memberIds = new Set(get(people).filter((p) => p.orgId === orgId).map((p) => p.id));
	orgs.update((list) => list.filter((o) => o.id !== orgId));
	people.update((list) => list.filter((p) => p.orgId !== orgId));
	machines.update((list) => list.filter((m) => !memberIds.has(m.personId)));
	review.update((list) => list.filter((r) => r.orgId !== orgId));
}

export function resolveReview(itemId: string, verdict: Verdict): void {
	const item = get(review).find((r) => r.id === itemId);
	if (!item) {
		return;
	}
	review.update((list) => list.map((r) => (r.id === itemId ? { ...r, verdict } : r)));
	machines.update((list) =>
		list.map((m) => ({
			...m,
			services: m.services.map((s) =>
				s.id === item.serviceId
					? {
							...s,
							verdict,
							flagged: verdict === 'pending',
							tunnel: verdict === 'banned' ? ('suspended' as const) : s.tunnel
						}
					: s
			)
		}))
	);
	if (verdict === 'banned') {
		suspendPerson(item.personId);
	}
}

// ---- live ticker ----------------------------------------------------------

let timer: ReturnType<typeof setInterval> | null = null;
let tickStep = 0;

/** Increments whenever a new 1-minute bucket rolls in, driving the chart slide-in animation. */
export const minutePulse: Writable<number> = writable(0);

function tick(): void {
	if (!get(live)) {
		return;
	}
	tickStep += 1;
	const advanceMinute = tickStep % 4 === 0;
	const now = Date.now();
	const fresh: LogEntry[] = [];

	machines.update((list) =>
		list.map((machine) => {
			const health = healthOf(machine);
			if (health === 'offline') {
				return machine;
			}
			const services = machine.services.map((service) => {
				if (service.tunnel !== 'open') {
					return service;
				}
				const expected = Math.max(0.08, service.requestsHour / 3600 / 1.5);
				const hasLog = Math.random() <= expected;
				let extraIn = 0;
				let extraOut = 0;
				if (hasLog) {
					const log = makeLog(service, machine);
					extraIn = log.bytesIn;
					extraOut = log.bytesOut;
					if (fresh.length < 8) {
						fresh.push(log);
					}
				}

				if (!advanceMinute) {
					return hasLog
						? {
								...service,
								requests: service.requests + 1,
								bytesIn: service.bytesIn + extraIn,
								bytesOut: service.bytesOut + extraOut
							}
						: service;
				}

				// Roll a new aligned 1-minute bucket across every open service at once.
				const shift = service.series.slice(1);
				const last = service.series[service.series.length - 1];
				const recent = service.series.slice(-30);
				const meanOut = recent.reduce((a, p) => a + p.bytesOut, 0) / recent.length;
				const meanIn = recent.reduce((a, p) => a + p.bytesIn, 0) / recent.length;
				const meanReq = recent.reduce((a, p) => a + p.requests, 0) / recent.length;
				// Smooth autoregressive step (70% previous minute + 30% mean with gentle noise)
				const waveFactor = 0.85 + Math.random() * 0.3;
				const nextOut = Math.round((last.bytesOut * 0.65 + meanOut * 0.35) * waveFactor);
				const nextIn = Math.round((last.bytesIn * 0.65 + meanIn * 0.35) * (0.85 + Math.random() * 0.3));
				const comp = 0.48 + Math.random() * 0.18;
				shift.push({
					ts: last.ts + 60_000,
					bytesIn: nextIn,
					bytesOut: nextOut,
					tunIn: Math.round(nextIn * comp),
					tunOut: Math.round(nextOut * comp),
					requests: Math.max(1, Math.round((last.requests * 0.65 + meanReq * 0.35) * waveFactor))
				});
				return {
					...service,
					requests: service.requests + (hasLog ? 1 : 0),
					bytesIn: service.bytesIn + extraIn,
					bytesOut: service.bytesOut + extraOut,
					series: shift
				};
			});
			return {
				...machine,
				lastSeenAt: new Date(now).toISOString(),
				online: true,
				services,
				series: machine.series.map((p, i) => {
					const svc = services
						.map((s) => s.series[i])
						.filter(Boolean)
						.reduce(
							(acc, pt) => ({
								ts: pt.ts,
								bytesIn: acc.bytesIn + pt.bytesIn,
								bytesOut: acc.bytesOut + pt.bytesOut,
								tunIn: acc.tunIn + pt.tunIn,
								tunOut: acc.tunOut + pt.tunOut,
								requests: acc.requests + pt.requests
							}),
							{ ts: p.ts, bytesIn: 0, bytesOut: 0, tunIn: 0, tunOut: 0, requests: 0 }
						);
					return svc;
				})
			};
		})
	);

	if (advanceMinute) {
		minutePulse.update((n) => n + 1);
	}

	if (fresh.length > 0 && get(capturingLogs)) {
		logs.update((list) => [...fresh, ...list].slice(0, LOG_CAP));
	}
}

export function startLive(): void {
	if (timer) {
		return;
	}
	tick();
	timer = setInterval(tick, 1500);
}

export function stopLive(): void {
	if (timer) {
		clearInterval(timer);
		timer = null;
	}
}

// ---- derived aggregates ---------------------------------------------------

export interface Totals {
	machines: number;
	online: number;
	services: number;
	openTunnels: number;
	requestsHour: number;
	bytesIn: number;
	bytesOut: number;
	flagged: number;
}

export function totalsOf(list: Machine[]): Totals {
	const services = list.flatMap((m) => m.services);
	return {
		machines: list.length,
		online: list.filter((m) => healthOf(m) === 'online').length,
		services: services.length,
		openTunnels: services.filter((s) => s.tunnel === 'open').length,
		requestsHour: services.reduce((a, s) => a + s.requestsHour, 0),
		bytesIn: services.reduce((a, s) => a + s.bytesIn, 0),
		bytesOut: services.reduce((a, s) => a + s.bytesOut, 0),
		flagged: services.filter((s) => s.flagged).length
	};
}
