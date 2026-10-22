/**
 * Global search over the parts of the fleet the signed-in role may see.
 *
 * The query language is a handful of field filters plus free text:
 * `org:"acme tls"` `machine:lab` `service:grafana` `user:sam` `host:…`.
 * `searchResults` is the single derived source the header field and the search
 * page both read, so they always agree.
 */
import { derived, get, writable, type Readable } from 'svelte/store';

import type { Machine, Org, Person, Role } from '#lib/mock/types';
import type { IconName } from '#lib/ui/icons';
import { current, visibleMachines, visibleOrgs, visiblePeople } from '#lib/mock/store';

export type Kind = 'machine' | 'service' | 'person' | 'org';

export interface SearchResult {
	kind: Kind;
	icon: IconName;
	label: string;
	sub: string;
	href: string;
	/** 0 = exact label, 1 = prefix, 2 = other. Used only for ordering. */
	score: number;
}

export const KIND_ORDER: Kind[] = ['machine', 'service', 'person', 'org'];

export const KIND_LABEL: Record<Kind, string> = {
	machine: 'Machines',
	service: 'Services',
	person: 'People',
	org: 'Organisations'
};

/** The field filters the query language understands. */
export const FILTERS: { key: string; help: string }[] = [
	{ key: 'machine', help: 'a machine name or hostname' },
	{ key: 'service', help: 'a service or hostname' },
	{ key: 'user', help: 'an owner name, slug or email' },
	{ key: 'org', help: 'an organisation name or slug' }
];

/** The query itself — the one piece of state the header and the page share. */
export const searchQuery = writable('');

interface Parsed {
	filters: { key: string; value: string }[];
	words: string[];
}

/** Splits `org:"acme tls" machine:lab nginx` into filters and free words. */
export function parseQuery(raw: string): Parsed {
	const filters: { key: string; value: string }[] = [];
	const words: string[] = [];
	const re = /(\w+):(?:"([^"]*)"|(\S+))|"([^"]*)"|(\S+)/g;
	let m: RegExpExecArray | null;
	while ((m = re.exec(raw)) !== null) {
		if (m[1]) {
			const key = m[1].toLowerCase();
			const value = (m[2] ?? m[3] ?? '').toLowerCase();
			const norm = key === 'person' || key === 'member' ? 'user' : key;
			if (FILTERS.some((f) => f.key === norm) || norm === 'host') {
				filters.push({ key: norm, value });
			} else {
				words.push(value);
			}
		} else {
			words.push((m[4] ?? m[5] ?? '').toLowerCase());
		}
	}
	return { filters, words };
}

interface Entity extends SearchResult {
	fields: Record<string, string>;
	text: string;
}

function buildEntities(
	role: Role,
	orgs: Org[],
	people: Person[],
	machines: Machine[]
): Entity[] {
	const entities: Entity[] = [];

	const personOf = (machine: Machine) => people.find((p) => p.id === machine.personId);
	const orgOf = (person?: Person) => orgs.find((o) => o.id === person?.orgId);
	const orgText = (org?: Org) => `${org?.name ?? ''} ${org?.slug ?? ''}`;
	const personText = (person?: Person) =>
		`${person?.name ?? ''} ${person?.slug ?? ''} ${person?.email ?? ''}`;

	for (const machine of machines) {
		const person = personOf(machine);
		const org = orgOf(person);
		entities.push({
			kind: 'machine',
			icon: 'machine',
			label: machine.name,
			sub: `${machine.hostname} · ${person?.name ?? '—'}`,
			href: `/app/machines/${machine.id}`,
			score: 0,
			fields: {
				org: orgText(org),
				user: personText(person),
				machine: `${machine.name} ${machine.hostname}`,
				service: machine.services.map((s) => `${s.name} ${s.hostname}`).join(' ')
			},
			text: `${machine.name} ${machine.hostname} ${machine.os} ${machine.agentVersion}`
		});
	}

	for (const machine of machines) {
		const person = personOf(machine);
		const org = orgOf(person);
		for (const service of machine.services) {
			entities.push({
				kind: 'service',
				icon: 'network',
				label: service.name,
				sub: `${service.hostname} · ${machine.name}`,
				href: `/app/machines/${machine.id}`,
				score: 0,
				fields: {
					org: orgText(org),
					user: personText(person),
					machine: `${machine.name} ${machine.hostname}`,
					service: `${service.name} ${service.hostname} ${service.target}`
				},
				text: `${service.name} ${service.hostname} ${service.target} ${service.tunnel}`
			});
		}
	}

	for (const person of people) {
		const org = orgOf(person);
		const mine = machines.filter((m) => m.personId === person.id);
		entities.push({
			kind: 'person',
			icon: 'users',
			label: person.name,
			sub: `${person.email} · ${org?.name ?? ''}`,
			href: `/app/people/${person.id}`,
			score: 0,
			fields: {
				org: orgText(org),
				user: personText(person),
				machine: mine.map((m) => `${m.name} ${m.hostname}`).join(' '),
				service: mine.flatMap((m) => m.services.map((s) => `${s.name} ${s.hostname}`)).join(' ')
			},
			text: `${person.name} ${person.slug} ${person.email} ${person.role} ${person.status}`
		});
	}

	// Organisations are only navigable for the fleet admin.
	if (role === 'super_admin') {
		for (const org of orgs) {
			const members = people.filter((p) => p.orgId === org.id);
			const theirMachines = machines.filter((m) => members.some((p) => p.id === m.personId));
			entities.push({
				kind: 'org',
				icon: 'building',
				label: org.name,
				sub: `${org.slug} · ${org.status}`,
				href: `/app/admin/orgs/${org.id}`,
				score: 0,
				fields: {
					org: orgText(org),
					user: members.map(personText).join(' '),
					machine: theirMachines.map((m) => `${m.name} ${m.hostname}`).join(' '),
					service: theirMachines
						.flatMap((m) => m.services.map((s) => `${s.name} ${s.hostname}`))
						.join(' ')
				},
				text: `${org.name} ${org.slug} ${org.status}`
			});
		}
	}

	return entities;
}

export function runSearch(
	raw: string,
	role: Role,
	orgs: Org[],
	people: Person[],
	machines: Machine[]
): SearchResult[] {
	const { filters, words } = parseQuery(raw);
	if (filters.length === 0 && words.length === 0) {
		return [];
	}
	const out: SearchResult[] = [];
	for (const entity of buildEntities(role, orgs, people, machines)) {
		let ok = true;
		for (const f of filters) {
			const hay =
				f.key === 'host'
					? `${entity.fields.machine} ${entity.fields.service}`
					: (entity.fields[f.key] ?? '');
			if (f.value !== '' && !hay.includes(f.value)) {
				ok = false;
				break;
			}
		}
		if (ok) {
			for (const word of words) {
				if (word !== '' && !entity.text.includes(word)) {
					ok = false;
					break;
				}
			}
		}
		if (!ok) {
			continue;
		}
		const first = words[0] ?? filters[0]?.value ?? '';
		const label = entity.label.toLowerCase();
		const score = label === first ? 0 : label.startsWith(first) ? 1 : 2;
		out.push({ ...entity, score });
	}
	return out
		.sort((a, b) => a.score - b.score || KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind))
		.slice(0, 40);
}

/** The reactive result set both surfaces render. */
export const searchResults: Readable<SearchResult[]> = derived(
	[searchQuery, current, visibleOrgs, visiblePeople, visibleMachines],
	([$q, $current, $orgs, $people, $machines]) =>
		runSearch($q, $current?.role ?? 'user', $orgs, $people, $machines)
);

export function clearSearch(): void {
	searchQuery.set('');
}

/** Non-reactive lookup for callers outside a component. */
export function resultsNow(): SearchResult[] {
	return runSearch(
		get(searchQuery),
		get(current)?.role ?? 'user',
		get(visibleOrgs),
		get(visiblePeople),
		get(visibleMachines)
	);
}
