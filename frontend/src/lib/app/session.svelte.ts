/**
 * The session, as the relay streams it (WVR-167).
 *
 * `GET /api/account/me` is an event stream and the console's single source of
 * truth for "what may I do": on connect, and every time it changes, the relay
 * sends a `state` event carrying the current level, the way up to every higher
 * level, and — while signed in — the identity and the next instant the level
 * drops. A `drop` event announces that drop a little before it lands, so the
 * console can warn instead of letting an action be refused by a second.
 *
 * The cookie is httpOnly, so asking is the only way to know. One stream serves
 * the whole tab: the root layout's load opens it and waits for its first frame,
 * so no page load runs before the level is known. An anonymous answer closes
 * it at once — a visitor reading the landing page holds no connection — and a
 * sign-in reopens it the moment the password step has opened a session.
 *
 * The console knows by itself which level each of its actions needs (see
 * {@link atLeast}); only the ways up depend on the account, so they come from
 * the relay.
 */
import { getContext, setContext } from 'svelte';

/**
 * How strongly the current session is authenticated: `basic` is the password
 * alone, `strong` adds the second factor, `certain` is `strong` plus a password
 * typed moments ago (what a sensitive action asks for).
 */
export type AuthLevel = 'none' | 'basic' | 'strong' | 'certain';

const RANK: Record<AuthLevel, number> = { none: 0, basic: 1, strong: 2, certain: 3 };

/** Whether `level` is enough for an action that needs `required`. */
export function atLeast(level: AuthLevel, required: AuthLevel): boolean {
	return RANK[level] >= RANK[required];
}

/**
 * One thing a person can do to climb, as the relay names it: sign in, enter the
 * emailed code, re-type the password. More arrive with more factors.
 */
export type Step = 'login' | 'verify_email_otp' | 'confirm_password';

/**
 * One step of a way up, with the level taking it would leave the session at.
 *
 * `reaches` comes from the relay because it depends on the proofs held now, not
 * on the step alone: entering the emailed code lands at `certain` moments after
 * a sign-in and at `strong` once the password proof has aged out.
 */
export interface PathStep {
	step: Step;
	reaches: AuthLevel;
}

/** One way up: the steps to take, in order. */
export type UpgradePath = PathStep[];

/** The ways up to one level, the preferred first. */
export interface LevelPaths {
	to: AuthLevel;
	options: UpgradePath[];
}

/** When the level next falls (Unix seconds, the relay's clock) and to what. */
export interface Drop {
	at: number;
	to: AuthLevel;
}

/** A drop announced ahead of time; `in` is the seconds left when it was sent. */
export interface DropNotice extends Drop {
	in: number;
}

export interface Me {
	id: number;
	name: string;
	/** Empty for an account with no email identity. */
	email: string;
	/** Whether the account has a password credential; not every sign-in method needs one. */
	has_password: boolean;
}

/** One `state` event. `me` and `drop` exist exactly while a session is live. */
export type SessionState =
	| { level: 'none'; paths: LevelPaths[] }
	| { level: 'basic' | 'strong' | 'certain'; paths: LevelPaths[]; me: Me; drop: Drop };

const STREAM_URL = '/api/account/me';

/** What a failed first connection tells the person. */
const UNREACHABLE = 'We could not verify your session. Try again.';

/** How long a caller waits for a level before giving up on the stream. */
const WAIT_MS = 10_000;

const NO_NOTICE: DropNotice = { at: 0, in: 0, to: 'none' };

class SessionStream {
	/** The latest `state`; anonymous until the first frame says otherwise. */
	state = $state<SessionState>({ level: 'none', paths: [] });
	/** Whether a first frame has ever arrived. */
	ready = $state(false);
	/** Why the first frame could not be read; empty once one has. */
	error = $state('');
	/** The pending drop announcement; `at` is 0 when there is none. */
	notice = $state<DropNotice>(NO_NOTICE);

	#source: EventSource | undefined;
	#waiters: { done: () => boolean; resolve: () => void }[] = [];

	/** The signed-in identity, or null when there is no session. */
	get user(): Me | null {
		return this.state.level === 'none' ? null : this.state.me;
	}

	get level(): AuthLevel {
		return this.state.level;
	}

	/** The ways to reach `level`, the preferred first; empty when already there. */
	pathsTo(level: AuthLevel): UpgradePath[] {
		return this.state.paths.find((paths) => paths.to === level)?.options ?? [];
	}

	/** Opens the stream unless one is already open. */
	start(): void {
		if (this.#source) {
			return;
		}
		const source = new EventSource(STREAM_URL, { withCredentials: true });
		this.#source = source;

		source.addEventListener('state', (event: MessageEvent<string>) => {
			let next: SessionState;
			try {
				next = JSON.parse(event.data) as SessionState;
			} catch {
				return;
			}
			this.state = next;
			this.ready = true;
			this.error = '';
			if (next.level === 'none' || next.drop.at !== this.notice.at) {
				this.notice = NO_NOTICE;
			}
			// Anonymous: nothing more will happen on this stream until a sign-in
			// starts, so do not hold it open (or let it reconnect).
			if (next.level === 'none') {
				this.#close(source);
			}
			this.#settle();
		});

		source.addEventListener('drop', (event: MessageEvent<string>) => {
			try {
				this.notice = JSON.parse(event.data) as DropNotice;
			} catch {
				// A malformed announcement is dropped; the state that follows is not.
			}
		});

		source.addEventListener('error', () => {
			// Before the first frame, say so — an unreachable relay is not a
			// signed-out visitor. After it, the last state stands while the
			// browser reconnects on its own.
			if (!this.ready) {
				this.error = UNREACHABLE;
				this.#settle();
			}
		});
	}

	/** Closes the stream and forgets the session (signing out). */
	stop(): void {
		if (this.#source) {
			this.#close(this.#source);
		}
		this.state = { level: 'none', paths: [] };
		this.notice = NO_NOTICE;
	}

	/**
	 * Stops listening but keeps the last state: for an action that is about to
	 * end the session and leave the page, so the guards do not react to the
	 * `none` frame the relay sends while the response is still in flight. Call
	 * {@link restart} if the action fails.
	 */
	detach(): void {
		if (this.#source) {
			this.#close(this.#source);
		}
	}

	/** Reopens the stream: a sign-in has started, or a retry was asked for. */
	restart(): void {
		if (this.#source) {
			this.#close(this.#source);
		}
		this.error = '';
		this.start();
	}

	/** Resolves once the first frame has arrived, or the first connection failed. */
	settled(): Promise<void> {
		return this.#wait(() => this.ready || this.error !== '');
	}

	/**
	 * Resolves once the stream reports at least `level` — the code accepted, a
	 * session opened — or after a bounded wait, so a caller never hangs on a
	 * stream that cannot deliver.
	 */
	reached(level: AuthLevel): Promise<void> {
		return this.#wait(() => this.ready && atLeast(this.state.level, level), WAIT_MS);
	}

	#close(source: EventSource): void {
		source.close();
		if (this.#source === source) {
			this.#source = undefined;
		}
	}

	#wait(done: () => boolean, timeoutMs = 0): Promise<void> {
		if (done()) {
			return Promise.resolve();
		}
		return new Promise((resolve) => {
			const waiter = { done, resolve };
			this.#waiters.push(waiter);
			if (timeoutMs > 0) {
				setTimeout(() => {
					this.#waiters = this.#waiters.filter((w) => w !== waiter);
					resolve();
				}, timeoutMs);
			}
		});
	}

	#settle(): void {
		const pending = this.#waiters;
		this.#waiters = [];
		for (const waiter of pending) {
			if (waiter.done()) {
				waiter.resolve();
			} else {
				this.#waiters.push(waiter);
			}
		}
	}
}

/**
 * The tab's one session stream. Loads read it directly (they run outside any
 * component); components go through {@link useSession}.
 */
export const session = new SessionStream();

export type Session = SessionStream;

const KEY = Symbol('weaver.session');

/** Publishes the session stream to the component tree. Root layout only. */
export function provideSession(): Session {
	setContext(KEY, session);
	return session;
}

/**
 * Reads the session published by the root layout. Throws when read outside its
 * subtree — a missing provider is a programming error, not a runtime state.
 */
export function useSession(): Session {
	const value = getContext<Session | undefined>(KEY);
	if (!value) {
		throw new Error('useSession() must be called under the root layout, which provides it.');
	}
	return value;
}
