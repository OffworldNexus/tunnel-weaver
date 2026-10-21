/**
 * Renders a device key fingerprint for display.
 *
 * The relay stores and sends a key in its one canonical text form
 * (`p256:<hex>` or `ed25519:<hex>`, lowercase); this only groups the hex bytes
 * in fours so a human can read them aloud and compare them out of band. It is
 * the same rendering everywhere a fingerprint appears.
 */
export function fingerprint(key: string): string {
	const colon = key.indexOf(':');
	if (colon < 0) {
		return key;
	}
	const algorithm = key.slice(0, colon);
	const hex = key.slice(colon + 1).toLowerCase();
	const grouped = hex.match(/.{1,4}/g)?.join(' ') ?? hex;
	return `${algorithm}:${grouped}`;
}
