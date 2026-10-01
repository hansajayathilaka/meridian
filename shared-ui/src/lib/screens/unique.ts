/**
 * First-wins de-duplication by key. Keyed `{#each}` blocks throw on duplicate keys, so a screen
 * must not hand one a list the adapter happened to return with repeats.
 */
export function uniqueBy<T>(items: readonly T[], key: (item: T) => string): readonly T[] {
  const seen: string[] = [];
  const out: T[] = [];
  for (const item of items) {
    const k = key(item);
    if (seen.includes(k)) continue;
    seen.push(k);
    out.push(item);
  }
  return out;
}
