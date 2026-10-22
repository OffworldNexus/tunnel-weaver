/** Aggregation helpers turning machines/services into chart series. */
import type { Machine, Service, TrafficPoint } from '#lib/mock/types';

export function sumSeries(parts: TrafficPoint[][]): TrafficPoint[] {
	if (parts.length === 0) {
		return [];
	}
	const points = Math.min(...parts.map((p) => p.length));
	const out: TrafficPoint[] = [];
	for (let i = 0; i < points; i += 1) {
		let bytesIn = 0;
		let bytesOut = 0;
		let tunIn = 0;
		let tunOut = 0;
		let requests = 0;
		for (const part of parts) {
			const p = part[part.length - points + i];
			bytesIn += p.bytesIn;
			bytesOut += p.bytesOut;
			tunIn += p.tunIn;
			tunOut += p.tunOut;
			requests += p.requests;
		}
		out.push({ ts: parts[0][parts[0].length - points + i].ts, bytesIn, bytesOut, tunIn, tunOut, requests });
	}
	return out;
}

export function machineSeries(list: Machine[]): TrafficPoint[] {
	return sumSeries(list.map((m) => m.series));
}

export function serviceSeries(list: Service[]): TrafficPoint[] {
	return sumSeries(list.map((s) => s.series));
}

export function pickTimes(points: TrafficPoint[]): number[] {
	return points.map((p) => p.ts);
}

export function pick(points: TrafficPoint[], key: keyof Omit<TrafficPoint, 'ts'>): number[] {
	return points.map((p) => p[key]);
}

/**
 * Bytes seen in the last sampled hour (last 60 minute buckets), summed across
 * the given machines.
 */
export function hourlyBytes(machines: Machine[], key: keyof Omit<TrafficPoint, 'ts'>): number {
	let total = 0;
	for (const machine of machines) {
		for (const point of machine.series.slice(-60)) {
			total += point[key];
		}
	}
	return total;
}

/**
 * Projects a rolling 30-day total from the last hour's rate. `shape` accounts
 * for the day/night troughs the one-hour window does not show; it is a
 * deliberate, documented fudge, not a measurement.
 */
export function projectedBytes(
	machines: Machine[],
	direction: 'out' | 'in' | 'both',
	days = 30,
	shape = 0.62
): number {
	const keys: (keyof Omit<TrafficPoint, 'ts'>)[] =
		direction === 'out' ? ['bytesOut'] : direction === 'in' ? ['bytesIn'] : ['bytesIn', 'bytesOut'];
	const hourly = keys.reduce((sum, key) => sum + hourlyBytes(machines, key), 0);
	return Math.round(hourly * 24 * days * shape);
}

/** Per-minute external bandwidth (`bytesIn + bytesOut`) over the last hour, for inline sparklines. */
export function externalSeries(machines: Machine[]): number[] {
	return machineSeries(machines)
		.slice(-60)
		.map((p) => p.bytesIn + p.bytesOut);
}

/**
 * Synthesises a deterministic minute-by-minute (or bucketed) series across a
 * custom `[startMs, endMs]` date range from the current baseline series.
 */
export function synthesiseRange(
	basePoints: TrafficPoint[],
	startMs: number,
	endMs: number
): TrafficPoint[] {
	if (basePoints.length === 0 || endMs <= startMs) {
		return basePoints;
	}
	const span = endMs - startMs;
	const buckets = Math.min(180, Math.max(30, Math.round(span / 60_000)));
	const step = span / Math.max(1, buckets - 1);
	const n = basePoints.length;
	const out: TrafficPoint[] = [];
	for (let i = 0; i < buckets; i += 1) {
		const ts = Math.round(startMs + i * step);
		const src = basePoints[(i * 7 + Math.floor(startMs / 3_600_000)) % n];
		const diurnal = 0.72 + 0.42 * Math.sin(((ts / 3_600_000) * Math.PI) / 12);
		out.push({
			ts,
			bytesIn: Math.round(src.bytesIn * diurnal),
			bytesOut: Math.round(src.bytesOut * diurnal),
			tunIn: Math.round(src.tunIn * diurnal),
			tunOut: Math.round(src.tunOut * diurnal),
			requests: Math.max(1, Math.round(src.requests * diurnal))
		});
	}
	return out;
}

/** The same projection for request counts. */
export function projectedRequests(machines: Machine[], days = 30, shape = 0.62): number {
	return Math.round(hourlyBytes(machines, 'requests') * 24 * days * shape);
}
