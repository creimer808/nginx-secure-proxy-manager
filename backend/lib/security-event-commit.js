const RETENTION_BATCH_SIZE = 500;

/**
 * Inserts events and advances collector-specific cursors in one transaction.
 * A preflight duplicate check avoids PostgreSQL's aborted-transaction state
 * after expected replay duplicates, while all other database errors fail closed.
 */
const writeSecurityEvents = async (trx, { events, cursors, state, retentionDays, nowMs = Date.now() }) => {
	let inserted = 0;
	for (const event of events) {
		// The schema carries two unique keys. A truncate-and-regrow of the same
		// inode reuses a segment's line offsets with new content, which produces a
		// fresh event_id but a duplicate (segment, offset) pair; preflighting only
		// event_id would let that roll back the whole batch and strand the cursors.
		const before = await trx("security_event")
			.where("event_id", event.event_id)
			.orWhere((builder) => builder.where("ingest_segment_id", event.ingest_segment_id).andWhere("ingest_line_offset", event.ingest_line_offset))
			.first("id");
		if (before) continue;
		await trx("security_event").insert({ ...event, created_on: new Date(nowMs) });
		inserted += 1;
	}

	for (const cursor of cursors) {
		const values = {
			file_key: cursor.file_key,
			file_path: cursor.file_path,
			byte_offset: cursor.byte_offset,
			content_fingerprint: cursor.content_fingerprint,
			fingerprint_size: cursor.fingerprint_size ?? 0,
			updated_on: new Date(nowMs),
		};
		const existing = await trx("security_log_cursor")
			.where("segment_id", cursor.segment_id)
			.andWhere("log_kind", cursor.log_kind)
			.first();
		if (existing) await trx("security_log_cursor").where("id", existing.id).update(values);
		else await trx("security_log_cursor").insert({ ...cursor, ...values });
	}

	const existingState = await trx("security_collector_state").first();
	const stateValues = { ...state, events_inserted: inserted };
	if (existingState) await trx("security_collector_state").where("id", existingState.id).update(stateValues);
	else await trx("security_collector_state").insert(stateValues);

	// One portable bounded batch per cycle prevents retention changes from
	// holding a long transaction or starving API traffic.
	const cutoff = nowMs - retentionDays * 86400 * 1000;
	const expired = await trx("security_event").select("id").where("occurred_at_ms", "<", cutoff).limit(RETENTION_BATCH_SIZE);
	if (expired.length) await trx("security_event").whereIn("id", expired.map((row) => row.id)).del();
	return inserted;
};

export { RETENTION_BATCH_SIZE, writeSecurityEvents };
