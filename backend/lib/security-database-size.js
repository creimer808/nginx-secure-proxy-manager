const firstNumericValue = (result) => {
	const values = Array.isArray(result) ? result.flat(2) : result?.rows || [result];
	for (const row of values) {
		if (row && typeof row === "object") {
			// Native storage queries alias their single result as bytes. Avoid
			// mistaking PostgreSQL metadata such as rowCount for a byte count.
			if (Object.hasOwn(row, "bytes")) {
				const numeric = Number(row.bytes);
				if (Number.isFinite(numeric) && numeric >= 0) return numeric;
			}
			const fields = Object.keys(row);
			if (fields.length === 1) {
				const numeric = Number(row[fields[0]]);
				if (Number.isFinite(numeric) && numeric >= 0) return numeric;
			}
		}
	}
	return null;
};

/** Driver-native measurement includes table and index storage where supported. */
const databaseStorageBytes = async (database) => {
	try {
		const client = database.client.config.client;
		if (["better-sqlite3", "sqlite3"].includes(client)) {
			const pages = firstNumericValue(await database.raw("PRAGMA page_count"));
			const pageSize = firstNumericValue(await database.raw("PRAGMA page_size"));
			return pages !== null && pageSize !== null ? pages * pageSize : null;
		}
		if (["mysql", "mysql2"].includes(client)) {
			return firstNumericValue(await database.raw("SELECT COALESCE(SUM(data_length + index_length), 0) AS bytes FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN ('security_event', 'security_log_cursor', 'security_collector_state')"));
		}
		if (["pg", "postgresql"].includes(client)) {
			return firstNumericValue(await database.raw("SELECT pg_total_relation_size('security_event') + pg_total_relation_size('security_log_cursor') + pg_total_relation_size('security_collector_state') AS bytes"));
		}
	} catch { return null; }
	return null;
};

export { databaseStorageBytes };
