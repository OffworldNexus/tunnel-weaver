/**
 * The modal a `certain`-gated action shows (WVR-165, WVR-163).
 *
 * Deleting the account and adding a passkey are the same shape: a sensitive
 * action whose *confirmation* must not appear before the proof it needs is
 * held. So the escalation popin comes first — proving the password, or asserting
 * with a passkey — and only then the modal. Never the two at once, and never the
 * modal outliving the proof: when the level lapses while the modal is open, the
 * modal is taken away and the person is handed straight back to the popin, which
 * puts them back where they were once they have proven themselves again.
 *
 * ```ts
 * const naming = certainModal();
 * // … <Dialog bind:open={naming.open}> — the button calls naming.begin()
 * ```
 *
 * Call it during component initialisation: it owns an effect, and that effect is
 * what performs the hand-off.
 */
import { atLeast, type AuthLevel, session } from './session.svelte';
import { climb } from './upgrade';

/** How a `certain`-gated modal is driven. */
export interface CertainModal {
	/** Whether the modal is showing. Bind it to the dialog's `open`. */
	open: boolean;
	/**
	 * Asks for the proof and shows the modal once it is held. The nominal way in:
	 * an action's button calls this, never `open` directly.
	 */
	begin(): Promise<void>;
	/** The person dismissed the modal. */
	close(): void;
}

/**
 * Makes a `certain`-gated modal.
 *
 * The effect is the whole point: a modal left open past the window would be a
 * confirmation that cannot be submitted when it is finally answered, so the
 * moment the level is gone the modal goes with it — and the escalation that
 * asked for the proof in the first place comes back.
 */
export function certainModal(required: AuthLevel = 'certain'): CertainModal {
	let open = $state(false);

	$effect(() => {
		if (open && !atLeast(session.level, required)) {
			open = false;
			void begin();
		}
	});

	async function begin(): Promise<void> {
		if (await climb(required)) {
			open = true;
		}
	}

	return {
		get open(): boolean {
			return open;
		},
		set open(value: boolean) {
			open = value;
		},
		begin,
		close() {
			open = false;
		}
	};
}
