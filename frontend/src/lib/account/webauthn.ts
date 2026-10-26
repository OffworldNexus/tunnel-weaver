/**
 * Passkeys in the browser (WVR-163).
 *
 * Glue and nothing else: it turns the JSON options the relay issues into the
 * objects the credential-management API takes, runs one ceremony, and hands the
 * browser's answer back as the JSON the relay parses. *Which* ceremony is the
 * relay's decision, and it says so in the options — a discoverable one comes
 * back with `mediation: conditional`, which is what makes the browser offer the
 * passkey in the sign-in field's autofill rather than in a modal of its own.
 *
 * Only the JSON entry points are used (`parseCreationOptionsFromJSON` and its
 * request twin), not hand-rolled base64url marshalling: every browser that can
 * do passkeys at all has had these for years, and the manual path would be a
 * good deal of untestable code to carry for the ones that have not.
 */

/** Why a ceremony did not produce a credential. */
export type CeremonyFailure = 'unsupported' | 'cancelled' | 'failed';

/** Whether this browser can run a ceremony at all. */
export function supported(): boolean {
	return (
		typeof window !== 'undefined' &&
		typeof PublicKeyCredential !== 'undefined' &&
		typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function' &&
		typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function'
	);
}

/** What every `begin` answers with: the handle, and the relay's options. */
export interface PasskeyOptions {
	handle: string;
	options: Record<string, unknown>;
}

/**
 * Why an exception out of a ceremony happened, as the console tells them apart.
 *
 * A dismissal and an abort are both "the person said no" — the OS prompt was
 * closed, or the console itself cancelled an autofill ceremony — and neither is
 * worth an error message. Everything else is.
 */
export function failureOf(error: unknown): CeremonyFailure {
	if (!supported()) {
		return 'unsupported';
	}
	if (
		error instanceof DOMException &&
		(error.name === 'NotAllowedError' || error.name === 'AbortError')
	) {
		return 'cancelled';
	}
	return 'failed';
}

/**
 * Runs a registration ceremony: the browser asks the person's authenticator to
 * create a credential, and answers with it.
 */
export async function createCredential(options: Record<string, unknown>): Promise<unknown> {
	const publicKey = PublicKeyCredential.parseCreationOptionsFromJSON(
		options.publicKey as PublicKeyCredentialCreationOptionsJSON
	);
	const credential = await navigator.credentials.create({ publicKey });
	if (!credential) {
		throw new Error('the authenticator returned no credential');
	}
	return (credential as PublicKeyCredential).toJSON();
}

/**
 * Runs an assertion ceremony.
 *
 * `signal` aborts a pending conditional (autofill) request: one started on page
 * load is live while the person types and submits the password form, so it has
 * to be able to stand down the moment the page leaves or the form is submitted.
 */
export async function getAssertion(
	options: Record<string, unknown>,
	{ signal, mediation }: { signal?: AbortSignal; mediation?: 'conditional' | 'optional' } = {}
): Promise<unknown> {
	const publicKey = PublicKeyCredential.parseRequestOptionsFromJSON(
		options.publicKey as PublicKeyCredentialRequestOptionsJSON
	);
	// The relay asks for `conditional` when it wants the passkey offered in the
	// field's autofill. A caller showing a picker of its own — the button, the
	// step-up popin — asks for `optional` instead: it is the same ceremony, and
	// the difference is only where the browser puts the choice.
	const wanted = mediation ?? (options.mediation === 'conditional' ? 'conditional' : 'optional');
	const credential = await navigator.credentials.get({ publicKey, mediation: wanted, signal });
	if (!credential) {
		throw new Error('the authenticator returned no credential');
	}
	return (credential as PublicKeyCredential).toJSON();
}
