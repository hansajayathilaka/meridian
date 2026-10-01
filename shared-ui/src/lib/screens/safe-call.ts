/**
 * Run a shell-supplied callback without letting it affect the operation that triggered it. The
 * operation has already succeeded by the time a notification fires, so a throwing callback must
 * not be reported to the user as a failure of that operation (and must not become an unhandled
 * rejection). The thrown value is dropped, not logged: it could carry identifiers.
 */
export function notify<A extends unknown[]>(
  callback: ((...args: A) => void) | undefined,
  ...args: A
): void {
  try {
    callback?.(...args);
  } catch {
    // Isolated by design.
  }
}
