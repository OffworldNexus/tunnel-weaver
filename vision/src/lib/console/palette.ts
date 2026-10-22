/** Colour helpers shared by the console, so a score reads the same everywhere. */
import type { AccountStatus, Health, OrgStatus, Verdict } from '#lib/mock/types';

export const CHART = ['var(--tw-c1)', 'var(--tw-c2)', 'var(--tw-c3)', 'var(--tw-c4)', 'var(--tw-c5)'];

/** 0–100 → green / amber / red. */
export function reputationColor(score: number): string {
	if (score >= 70) {
		return 'var(--tw-online)';
	}
	if (score >= 45) {
		return 'var(--tw-idle)';
	}
	return 'var(--tw-danger)';
}

export function reputationLabel(score: number): string {
	if (score >= 85) {
		return 'Good';
	}
	if (score >= 70) {
		return 'Fair';
	}
	if (score >= 45) {
		return 'Watch';
	}
	if (score >= 25) {
		return 'At risk';
	}
	return 'Bad';
}

export function healthColor(h: Health): string {
	return h === 'online' ? 'var(--tw-online)' : h === 'idle' ? 'var(--tw-idle)' : 'var(--tw-offline)';
}

export function healthLabel(h: Health): string {
	return h === 'online' ? 'Online' : h === 'idle' ? 'Idle' : 'Offline';
}

export function accountColor(s: AccountStatus): 'ok' | 'warn' | 'danger' | 'muted' {
	if (s === 'active') {
		return 'ok';
	}
	if (s === 'invited') {
		return 'warn';
	}
	return s === 'suspended' ? 'danger' : 'muted';
}

export function orgColor(s: OrgStatus): 'ok' | 'danger' {
	return s === 'active' ? 'ok' : 'danger';
}

export function verdictColor(v: Verdict): 'ok' | 'warn' | 'danger' | 'muted' {
	if (v === 'cleared') {
		return 'ok';
	}
	if (v === 'pending') {
		return 'warn';
	}
	if (v === 'banned') {
		return 'danger';
	}
	return 'muted';
}

/** HTTP status → a chart colour: classes are coloured, everything else muted. */
export function statusColor(status: number): string {
	if (status >= 500) {
		return 'var(--tw-danger)';
	}
	if (status >= 400) {
		return 'var(--tw-idle)';
	}
	if (status >= 300) {
		return 'var(--tw-c3)';
	}
	return 'var(--tw-online)';
}

export function methodColor(method: string): string {
	switch (method) {
		case 'GET':
			return 'var(--tw-c3)';
		case 'POST':
			return 'var(--tw-c2)';
		case 'PUT':
			return 'var(--tw-c5)';
		case 'DELETE':
			return 'var(--tw-danger)';
		default:
			return 'var(--tw-muted)';
	}
}
