import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import knex from "knex";
import errs from "../lib/error.js";
import { up as securityMigrationUp, down as securityMigrationDown } from "../migrations/20260813120000_security_events.js";
import { up as progressMigrationUp, down as progressMigrationDown } from "../migrations/20260814120000_security_telemetry_progress.js";
let configureSecurityApiForTesting;
let getEvent;
let listEvents;
let getRetention;
let listLogFiles;
let readLog;
let resetSecurityApiTestState;
let updateRetention;
let database;
let logDirectory;
const now = Date.now();

const access = ({ userId, visibility = "user", admin = false, allowed = true } = {}) => ({
	can: async () => {
		if (!allowed) throw new errs.PermissionError();
		return { roles: admin ? ["admin"] : ["user"], permission_visibility: visibility };
	},
	token: { getUserId: () => userId },
});

const event = (overrides = {}) => ({
	occurred_at_ms: now,
	created_on: new Date(now),
	proxy_host_id: 1,
	source_kind: "security_access",
	event_id: "event-00000000000001",
	event_type: "http_status",
	severity: "medium",
	request_uri: "/blocked?token=example",
	status: 403,
	ingest_segment_id: "segment-1",
	ingest_line_offset: 0,
	...overrides,
});

const insertHost = (id, owner, isDeleted = 0) => database("proxy_host").insert({ id, owner_user_id: owner, is_deleted: isDeleted });

before(async () => {
	// security-api imports the application's lazy database factory. Point its
	// fallback SQLite/key files at a writable temporary directory before loading
	// the module; configured test queries replace that factory below.
	const configDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "security-api-config-"));
	process.env.DB_SQLITE_FILE = path.join(configDirectory, "fallback.sqlite");
	process.env.NODE_ENV = "test";
	process.env.NODE_CONFIG_DIR = configDirectory;
	process.env.NSPM_KEYS_FILE = path.join(configDirectory, "keys.json");
	({ configureSecurityApiForTesting, getEvent, getRetention, listEvents, listLogFiles, readLog, resetSecurityApiTestState, updateRetention } = await import("./security-api.js"));
	logDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "security-api-"));
	database = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
	await database.schema.createTable("proxy_host", (table) => {
		table.integer("id").primary();
		table.integer("owner_user_id").notNullable();
		table.integer("is_deleted").notNullable().defaultTo(0);
	});
	await database.schema.createTable("setting", (table) => { table.string("id").primary(); table.string("value").notNullable(); });
	await database.schema.createTable("audit_log", (table) => {
		table.increments("id"); table.integer("user_id").notNullable(); table.string("action").notNullable(); table.string("object_type").notNullable(); table.integer("object_id").notNullable(); table.json("meta").notNullable(); table.dateTime("created_on").notNullable(); table.dateTime("modified_on").notNullable();
	});
	await securityMigrationUp(database);
	await progressMigrationUp(database);
	configureSecurityApiForTesting({ database, logDirectory });
});

after(async () => {
	resetSecurityApiTestState();
	await progressMigrationDown(database);
	await securityMigrationDown(database);
	await database.destroy();
	fs.rmSync(logDirectory, { recursive: true, force: true });
});

describe("security API database-backed authorization and raw-log boundaries", () => {
	it("enforces owner, visibility=all, ownership changes, deleted/orphan events, and guessed IDs", async () => {
		await insertHost(1, 10);
		await insertHost(2, 20);
		await insertHost(3, 30, 1);
		await database("security_event").insert([
			event({ id: 1, event_id: "event-00000000000001", proxy_host_id: 1, ingest_line_offset: 1 }),
			event({ id: 2, event_id: "event-00000000000002", proxy_host_id: 2, ingest_line_offset: 2 }),
			event({ id: 3, event_id: "event-00000000000003", proxy_host_id: 3, ingest_line_offset: 3 }),
			event({ id: 4, event_id: "event-00000000000004", proxy_host_id: null, ingest_line_offset: 4 }),
		]);
		const owner = await listEvents(access({ userId: 10 }), { from: String(now - 1), to: String(now + 1) });
		assert.deepEqual(owner.items.map((row) => row.id), [1]);
		const visibilityAll = await listEvents(access({ userId: 99, visibility: "all" }), { from: String(now - 1), to: String(now + 1) });
		assert.deepEqual(visibilityAll.items.map((row) => row.id), [2, 1]);
		await assert.rejects(() => getEvent(access({ userId: 10 }), "event-00000000000002"), { status: 404 });
		assert.equal((await getEvent(access({ userId: 1, admin: true }), "event-00000000000004")).id, 4);
		await database("proxy_host").where("id", 1).update({ owner_user_id: 20 });
		assert.equal((await listEvents(access({ userId: 10 }), { from: String(now - 1), to: String(now + 1) })).items.length, 0);
		assert.equal((await listEvents(access({ userId: 20 }), { from: String(now - 1), to: String(now + 1) })).items.length, 2);
		await assert.rejects(() => listEvents(access({ userId: 10, allowed: false }), {}), { status: 403 });
	});

	it("resolves only authorized allowlisted raw files and prevents global, symlink, hardlink, rotation, and cursor bypasses", async () => {
		await insertHost(9, 10);
		fs.writeFileSync(path.join(logDirectory, "proxy-host-9_security.log"), "one\ntwo\nthree\n");
		fs.writeFileSync(path.join(logDirectory, "fallback_http_access.log"), "global\n");
		fs.symlinkSync("/etc/passwd", path.join(logDirectory, "proxy-host-9_error.log"));
		const hardlinkSource = path.join(logDirectory, "hardlink-source.log");
		fs.writeFileSync(hardlinkSource, "hard linked\n");
		fs.linkSync(hardlinkSource, path.join(logDirectory, "proxy-host-9_access.log"));
		const owner = access({ userId: 10 });
		assert.deepEqual(await listLogFiles(owner, { proxy_host_id: "9", kind: "security" }), [{ rotation: "current", compressed: false, available: true }]);
		assert.deepEqual(await listLogFiles(access({ userId: 1, admin: true }), { target: "global", kind: "access" }), [{ rotation: "current", compressed: false, available: true }]);
		await assert.rejects(() => listLogFiles(access({ userId: 10 }), { target: "global", kind: "access" }), { status: 403 });
		await assert.rejects(() => readLog(owner, { proxy_host_id: "9", kind: "error" }), { status: 404 });
		await assert.rejects(() => readLog(owner, { proxy_host_id: "9", kind: "access" }), { status: 404 });
		await assert.rejects(() => readLog(owner, { proxy_host_id: "9", kind: "security", rotation: ".999.gz" }), { status: 400 });
		await assert.rejects(() => readLog(owner, { proxy_host_id: "9", kind: "security", cursor: "not-a-cursor" }), { status: 400 });
		const page = await readLog(owner, { proxy_host_id: "9", kind: "security", direction: "forward", limit: "1" });
		assert.equal(page.lines[0].line, "one");
		assert.equal(page.partial, true);
		assert.ok(page.next_cursor);
		const next = await readLog(owner, { proxy_host_id: "9", kind: "security", direction: "forward", cursor: page.next_cursor, limit: "1" });
		assert.equal(next.lines[0].line, "two");
	});

	it("exposes the fallback security log and the configuration upgrade status to administrators only", async () => {
		fs.writeFileSync(path.join(logDirectory, "fallback_security.log"), "fallback line\n");
		const admin = access({ userId: 1, admin: true });
		assert.deepEqual(await listLogFiles(admin, { target: "global", kind: "security" }), [{ rotation: "current", compressed: false, available: true }]);
		assert.equal((await readLog(admin, { target: "global", kind: "security" })).lines[0].line, "fallback line");
		await assert.rejects(() => listLogFiles(access({ userId: 10 }), { target: "global", kind: "security" }), { status: 403 });
		await assert.rejects(() => readLog(access({ userId: 10 }), { target: "global", kind: "security" }), { status: 403 });

		await database("security_config_state").insert({ last_run_on: new Date(), hosts_total: 3, hosts_upgraded: 2, hosts_skipped: 1, hosts_pending: 0, reload_deferred: true, last_error_summary: "proxy host 7: missing certificate" });
		const settings = await getRetention(admin);
		assert.equal(settings.nginx_upgrade.hosts_upgraded, 2);
		assert.equal(settings.nginx_upgrade.hosts_skipped, 1);
		assert.equal(settings.nginx_upgrade.reload_deferred, true);
		assert.equal((await getRetention(access({ userId: 10 }))).nginx_upgrade, undefined);
	});

	it("makes retention updates administrator-only and rolls back the setting if its audit write fails", async () => {
		await database("setting").insert({ id: "security-event-retention-days", value: "30" });
		await assert.rejects(() => updateRetention(access({ userId: 10 }), 7), { status: 403 });
		await updateRetention(access({ userId: 1, admin: true }), 7);
		assert.equal((await database("setting").where("id", "security-event-retention-days").first()).value, "7");
		assert.equal((await database("audit_log").where("action", "security.event-retention.update").first()).user_id, 1);
		await database.schema.dropTable("audit_log");
		await assert.rejects(() => updateRetention(access({ userId: 1, admin: true }), 365));
		assert.equal((await database("setting").where("id", "security-event-retention-days").first()).value, "7");
	});
});
