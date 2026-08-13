import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import knex from "knex";
import { writeSecurityEvents } from "./security-event-commit.js";

let db;
const state = { last_started_on: new Date(), last_completed_on: new Date(), last_error_on: null, last_error_summary: null, bytes_read: 1, lines_read: 1, malformed_lines: 0, files_pending: 0, limit_reached: false, database_high_water_reached: false, raw_log_disk_high_water_reached: false };
const event = (overrides = {}) => ({ occurred_at_ms: Date.now(), proxy_host_id: 1, source_kind: "security_access", event_type: "http_status", severity: "low", event_id: "event-1", ingest_segment_id: "segment", ingest_line_offset: 0, ...overrides });
const cursor = (overrides = {}) => ({ segment_id: "segment", log_kind: "security", file_key: "dev:ino", file_path: "/safe/log", byte_offset: 10, content_fingerprint: "fingerprint", ...overrides });

before(async () => {
	db = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
	await db.schema.createTable("security_event", (table) => { table.increments(); table.bigInteger("occurred_at_ms"); table.dateTime("created_on"); table.integer("proxy_host_id"); table.string("source_kind"); table.string("event_type"); table.string("severity"); table.string("event_id").unique(); table.string("ingest_segment_id"); table.bigInteger("ingest_line_offset"); table.unique(["ingest_segment_id", "ingest_line_offset"]); });
	await db.schema.createTable("security_log_cursor", (table) => { table.increments(); table.string("segment_id"); table.string("log_kind"); table.string("file_key"); table.string("file_path"); table.bigInteger("byte_offset"); table.string("content_fingerprint"); table.dateTime("updated_on"); table.unique(["segment_id", "log_kind"]); });
	await db.schema.createTable("security_collector_state", (table) => { table.increments(); table.dateTime("last_started_on"); table.dateTime("last_completed_on"); table.dateTime("last_error_on"); table.string("last_error_summary"); table.bigInteger("bytes_read"); table.bigInteger("lines_read"); table.bigInteger("events_inserted"); table.bigInteger("malformed_lines"); table.bigInteger("files_pending"); table.boolean("limit_reached"); table.boolean("database_high_water_reached"); table.boolean("raw_log_disk_high_water_reached"); });
});
after(() => db.destroy());

describe("security event commit", () => {
	it("deduplicates replayed events and advances its separate cursor", async () => {
		await db.transaction((trx) => writeSecurityEvents(trx, { events: [event()], cursors: [cursor()], state, retentionDays: 30 }));
		await db.transaction((trx) => writeSecurityEvents(trx, { events: [event()], cursors: [cursor({ byte_offset: 20 })], state, retentionDays: 30 }));
		assert.equal(Number((await db("security_event").count("id as count").first()).count), 1);
		assert.equal((await db("security_log_cursor").first()).byte_offset, 20);
	});

	it("rolls events and cursors back together", async () => {
		await assert.rejects(db.transaction(async (trx) => {
			await writeSecurityEvents(trx, { events: [event({ event_id: "rollback", ingest_segment_id: "rollback" })], cursors: [cursor({ segment_id: "rollback" })], state, retentionDays: 30 });
			throw new Error("force rollback");
		}));
		assert.equal(await db("security_event").where("event_id", "rollback").first(), undefined);
		assert.equal(await db("security_log_cursor").where("segment_id", "rollback").first(), undefined);
	});

	it("removes expired events in batches", async () => {
		await db("security_event").insert(event({ event_id: "expired", ingest_segment_id: "expired", occurred_at_ms: 1 }));
		await db.transaction((trx) => writeSecurityEvents(trx, { events: [], cursors: [], state, retentionDays: 7, nowMs: Date.now() }));
		assert.equal(await db("security_event").where("event_id", "expired").first(), undefined);
	});
});
