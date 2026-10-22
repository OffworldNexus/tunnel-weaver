/** Geometry helpers for the hand-rolled SVG charts. No chart dependency. */

/** One named series in a chart. */
export interface ChartSeries {
	label: string;
	color: string;
	points: number[];
}

export type RangePreset = '1h' | '3h' | '24h' | '7d' | 'custom';

/** A category in the active-vs-total grouped bars. */
export interface BarGroup {
	label: string;
	active: number;
	total: number;
}

export function extent(values: number[]): [number, number] {
	if (values.length === 0) {
		return [0, 1];
	}
	let lo = values[0];
	let hi = values[0];
	for (const v of values) {
		if (v < lo) {
			lo = v;
		}
		if (v > hi) {
			hi = v;
		}
	}
	return [lo, hi];
}

export interface Scale {
	x: (i: number) => number;
	y: (v: number) => number;
	lo: number;
	hi: number;
}

export function scale(values: number[], width: number, height: number, pad = 2): Scale {
	const [rawLo, rawHi] = extent(values);
	const lo = Math.min(0, rawLo);
	const hi = rawHi === lo ? lo + 1 : rawHi;
	const n = Math.max(1, values.length - 1);
	return {
		lo,
		hi,
		x: (i: number) => (i / n) * width,
		y: (v: number) => height - pad - ((v - lo) / (hi - lo)) * (height - pad * 2)
	};
}

/** A polyline through the values. */
export function linePath(values: number[], s: Scale): string {
	return values.map((v, i) => `${i === 0 ? 'M' : 'L'}${s.x(i).toFixed(2)} ${s.y(v).toFixed(2)}`).join(' ');
}

/** The polyline closed to the baseline, for a filled area. */
export function areaPath(values: number[], s: Scale, height: number): string {
	if (values.length === 0) {
		return '';
	}
	const base = height - 2;
	return `${linePath(values, s)} L${s.x(values.length - 1).toFixed(2)} ${base} L${s.x(0).toFixed(2)} ${base} Z`;
}

/** A filled band between a lower and an upper edge, for stacked areas. */
export function bandPath(upper: number[], lower: number[], s: Scale): string {
	if (upper.length === 0) {
		return '';
	}
	const up = upper
		.map((v, i) => `${i === 0 ? 'M' : 'L'}${s.x(i).toFixed(2)} ${s.y(v).toFixed(2)}`)
		.join(' ');
	const down: string[] = [];
	for (let i = lower.length - 1; i >= 0; i -= 1) {
		down.push(`L${s.x(i).toFixed(2)} ${s.y(lower[i]).toFixed(2)}`);
	}
	return `${up} ${down.join(' ')} Z`;
}

/** Running totals: `stack[i][j]` is the sum of series 0..i at point j. */
export function stackUp(series: number[][]): number[][] {
	const out: number[][] = [];
	let running: number[] | null = null;
	for (const points of series) {
		running = running ? running.map((v, i) => v + points[i]) : [...points];
		out.push(running);
	}
	return out;
}

/** `nice` round tick values for a y-axis. */
export function ticks(lo: number, hi: number, target = 4): number[] {
	if (hi <= lo) {
		return [lo];
	}
	const span = hi - lo;
	const raw = span / target;
	const mag = 10 ** Math.floor(Math.log10(raw));
	const norm = raw / mag;
	const step = (norm >= 5 ? 10 : norm >= 2 ? 5 : norm >= 1 ? 2 : 1) * mag;
	const out: number[] = [];
	for (let v = Math.ceil(lo / step) * step; v <= hi + 1e-9; v += step) {
		out.push(v);
	}
	return out;
}
