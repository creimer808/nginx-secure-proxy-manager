#!/usr/bin/env node

/**
 * Repeatable local sizing probe for the detailed-event migration. It deliberately
 * reports measurements instead of enforcing wall-clock thresholds: host disks,
 * SQLite builds, and CI runners vary too much for timing assertions to be useful.
 *
 * Run from backend: node scripts/security-events-benchmark.js [event-count]
 */
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import knex from "knex";
import { up, down } from "../migrations/20260813120000_security_events.js";
import { writeSecurityEvents } from "../lib/security-event-commit.js";

const eventCount = Number.parseInt(process.argv[2] || "10000", 10);
if (!Number.isSafeInteger(eventCount) || eventCount < 1 || eventCount > 100000) {
	throw new Error("event-count must be an integer from 1 through 100000");
}
const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "security-events-benchmark-")), "events.sqlite");
const database = knex({ client: "better-sqlite3", connection: { filename: file }, useNullAsDefault: true });
const now = Date.now();
const event = (index) => ({
	occurred_at_ms: now - index,
	proxy_host_id: 1,
	source_kind: "security_access",
	event_id: `benchmark-${String(index).padStart(12, "0")}`,
	event_type: "http_status",
	severity: "medium",
	client_ip: `192.0.2.${(index % 254) + 1}`,
	method: "GET",
	request_uri: `/benchmark/${index}?sample=${"x".repeat(96)}`,
	status: index % 5 === 0 ? 500 : 404,
	ingest_segment_id: "benchmark-segment",
	ingest_line_offset: index,
});

try {
	await up(database);
	const started = performance.now();
	for (let offset = 0; offset < eventCount; offset += 500) {
		const events = Array.from({ length: Math.min(500, eventCount - offset) }, (_, index) => event(offset + index));
		await database.transaction((trx) => writeSecurityEvents(trx, {
			events,
			cursors: [],
			state: { last_started_on: new Date(), last_completed_on: new Date(), bytes_read: 0, lines_read: 0, malformed_lines: 0, files_pending: 0, limit_reached: false, database_high_water_reached: false, raw_log_disk_high_water_reached: false },
			retentionDays: 365,
		}));
	}
	const ingestMs = performance.now() - started;
	const queryStarted = performance.now();
	const queryRows = await database("security_event").where("status", ">=", 500).orderBy("occurred_at_ms", "desc").limit(50);
	const queryMs = performance.now() - queryStarted;
	const retentionStarted = performance.now();
	await database.transaction((trx) => writeSecurityEvents(trx, {
		events: [], cursors: [],
		state: { last_started_on: new Date(), last_completed_on: new Date(), bytes_read: 0, lines_read: 0, malformed_lines: 0, files_pending: 0, limit_reached: false, database_high_water_reached: false, raw_log_disk_high_water_reached: false },
		retentionDays: 7,
		nowMs: now + 8 * 86400 * 1000,
	}));
	const retentionMs = performance.now() - retentionStarted;
	const size = fs.statSync(file).size;
	console.log(JSON.stringify({
		event_count: eventCount,
		ingest_ms: Math.round(ingestMs),
		events_per_second: Math.round(eventCount / (ingestMs / 1000)),
		common_query_ms: Math.round(queryMs),
		common_query_rows: queryRows.length,
		retention_batch_ms: Math.round(retentionMs),
		database_bytes: size,
		bytes_per_10000_events: Math.round((size / eventCount) * 10000),
		remaining_after_one_retention_batch: Number((await database("security_event").count("id as count").first()).count),
	}, null, 2));
} finally {
	await down(database);
	await database.destroy();
	fs.rmSync(path.dirname(file), { recursive: true, force: true });
}
