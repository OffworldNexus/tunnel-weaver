/**
 * The machines endpoints of the account API: the signed-in person's machines,
 * read and mutated through the same-origin JSON client. Every call returns the
 * raw `ApiResult` so the page can tell an error from an empty list.
 */
import { api } from '#lib/account/api';

/** A service a machine declares, with the hostnames the relay serves for it. */
export interface MachineService {
	/** The service label, e.g. `web`. */
	name: string;
	/** The public hostnames currently linked to the service; may be empty. */
	hostnames: string[];
	/** Whether any of its hostnames is currently routed (its tunnel is up). */
	active: boolean;
	/** Traffic over the last 30 days. */
	usage_30d: Usage30d;
}

/** A machine's traffic over the console's reporting window (30 days). */
export interface Usage30d {
	/** Bytes the relay received from visitors. */
	bytes_in: number;
	/** Bytes the relay sent to visitors. */
	bytes_out: number;
	/** Visitor requests the relay carried. */
	requests: number;
}

/** A paired machine, as the console renders it. */
export interface Machine {
	id: number;
	name: string;
	/** Derived from the live tunnel registry; never persisted. */
	online: boolean;
	/** Unix seconds of the last minute the machine served, or `null` if never. */
	last_seen_at: number | null;
	/** Unix seconds the machine was paired. */
	paired_at: number;
	/** The canonical key text (`p256:<hex>`); group it with `fingerprint()`. */
	fingerprint: string;
	/** Traffic over the last 30 days. */
	usage_30d: Usage30d;
	services: MachineService[];
}

/** A page of the person's machines, with the metadata the pager renders. */
export interface MachinePage {
	machines: Machine[];
	/** The 1-based page the relay returned — it clamps what was asked for. */
	page: number;
	per_page: number;
	total: number;
	page_count: number;
}

/** The filters and paging the machines collection accepts. */
export interface MachineQuery {
	page?: number;
	perPage?: number;
	/** A case-insensitive substring of the machine name. */
	q?: string;
	/** `all` (the default), `online` or `offline`. */
	health?: 'all' | 'online' | 'offline';
}

/** `GET /api/account/machines` — one page of the signed-in person's machines. */
export function listMachines({ page, perPage, q, health }: MachineQuery = {}) {
	const params = new URLSearchParams();
	if (page !== undefined) {
		params.set('page', String(page));
	}
	if (perPage !== undefined) {
		params.set('per_page', String(perPage));
	}
	if (q) {
		params.set('q', q);
	}
	if (health && health !== 'all') {
		params.set('health', health);
	}
	const query = params.toString();
	const suffix = query ? `?${query}` : '';
	return api<MachinePage>(`/api/account/machines${suffix}`);
}

/** `GET /api/account/machines/{id}` — one machine. */
export function getMachine(id: number) {
	return api<Machine>(`/api/account/machines/${id}`);
}

/** `POST /api/account/machines/{id}/rename` — rename, re-deriving its hostnames. */
export function renameMachine(id: number, name: string) {
	return api<{ ok: boolean; name: string }>(`/api/account/machines/${id}/rename`, { name });
}

/** `POST /api/account/machines/{id}/disconnect` — drop the live tunnel, keep the key. */
export function disconnectMachine(id: number) {
	return api<{ ok: boolean; disconnected: boolean }>(`/api/account/machines/${id}/disconnect`, {});
}

/** `POST /api/account/machines/{id}/revoke` — revoke the key and delete the machine. */
export function revokeMachine(id: number) {
	return api<{ ok: boolean }>(`/api/account/machines/${id}/revoke`, {});
}
