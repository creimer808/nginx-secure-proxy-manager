/**
 * A bounded, time-to-live memo for read-only security aggregates.
 *
 * Both the overview and the findings page run a fixed set of GROUP BY queries
 * over an unbounded event table, and both are polled by a page that refreshes.
 * Serving a rollup a few seconds stale costs nothing; re-deriving it on every
 * refresh scans the event table again per aggregate.
 *
 * The bound matters as much as the TTL: the cache key includes the asking
 * actor, so a large user population would otherwise grow this without limit.
 * Map iterates in insertion order, so evicting the first key drops the oldest
 * entry.
 */
const createMemo = ({ ttlMs, maxEntries }) => {
	const entries = new Map();
	return {
		read(key) {
			const entry = entries.get(key);
			if (!entry) return null;
			if (entry.expiresAt <= Date.now()) {
				entries.delete(key);
				return null;
			}
			return entry.value;
		},
		write(key, value) {
			if (entries.size >= maxEntries) entries.delete(entries.keys().next().value);
			entries.set(key, { value, expiresAt: Date.now() + ttlMs });
			return value;
		},
		clear() {
			entries.clear();
		},
	};
};

export { createMemo };
