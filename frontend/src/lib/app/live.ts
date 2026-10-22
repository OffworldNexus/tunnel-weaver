/**
 * The console's live half: one SSE subscription to one account-API URL.
 *
 * The relay answers `Accept: text/event-stream` with the same JSON body as the
 * plain call, immediately and again on every change. So a page keeps its `load`
 * for the first paint (and the 401 redirect), then adopts each pushed body as it
 * arrives. `EventSource` reconnects on its own, and every server frame is a full
 * snapshot, so a reconnect needs no replay.
 */

/**
 * Opens a stream for `url`, delivering each parsed snapshot to `onData`.
 *
 * Returns a closer for the calling effect's cleanup: navigating away, or to a
 * different query, must drop the old stream rather than leak it.
 */
export function streamJson<T>(url: string, onData: (data: T) => void): () => void {
	const source = new EventSource(url, { withCredentials: true });

	source.onmessage = (event: MessageEvent<string>) => {
		try {
			onData(JSON.parse(event.data) as T);
		} catch {
			// A frame that does not parse is skipped; the next snapshot is full.
		}
	};

	// The session behind the stream ended (logout, or a password change that
	// invalidated every session). Close so the browser does not reconnect into a
	// loop, and send the person back to sign in.
	source.addEventListener('expired', () => {
		source.close();
		window.location.assign('/sign-in');
	});

	// The streamed resource no longer exists — a machine revoked in another tab.
	// Only a machine's detail can reach this; send the person to the list, where
	// the machine is already gone.
	source.addEventListener('gone', () => {
		source.close();
		window.location.assign('/app/machines');
	});

	return () => source.close();
}
