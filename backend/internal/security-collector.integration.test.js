import assert from "node:assert/strict";
import { after, afterEach, before, beforeEach, describe, it } from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import knex from "knex";
import { up as eventsUp, down as eventsDown } from "../migrations/20260813120000_security_events.js";
import { up as progressUp, down as progressDown } from "../migrations/20260814120000_security_telemetry_progress.js";

let collector;
let candidateFiles;
let configureSecurityCollectorForTesting;
let resetSecurityCollectorTestState;
let FALLBACK_HOST_ID;

/**
 * These tests drive the collector's real entry point. Root cause B of the
 * v0.1.3 remediation — a cycle that spent its whole budget fingerprinting and
 * could therefore never advance a cursor — shipped because `collector.fetch()`
 * was unreachable from outside a container.
 */

let temp = "";
let database;
let discoverHosts;
const HOST = { id: 1, domain_names: ["one.test"], owner_user_id: 3 };

const securityLine = (index, overrides = {}) => {
	const occurred = Date.UTC(2026, 7, 13, 12, 0, 0) + index * 1000;
	const iso = new Date(occurred).toISOString().replace(/\.\d{3}Z$/, "Z");
	return JSON.stringify({
		schema_version: "1", ruleset_version: "2026-08-13", request_id: `request-${index}`, timestamp: iso, msec: `${Math.floor(occurred / 1000)}.000`,
		proxy_host_id: "1", rule_id: "", rule_category: "", rule_action: "", event_type: "http_status", severity: "low",
		remote_addr: "203.0.113.7", realip_remote_addr: "203.0.113.7", remote_port: "51000", request_method: "GET", scheme: "https", host: "one.test",
		request_uri: `/missing/${index}`, server_protocol: "HTTP/1.1", status: "404", upstream_status: "", request_length: "120", body_bytes_sent: "24",
		request_time: "0.010", upstream_addr: "", upstream_response_time: "", ssl_protocol: "TLSv1.3", ssl_cipher: "TLS_AES_256_GCM_SHA384",
		remote_user: "", http_user_agent: "scanner/1.0", http_referer: "", ...overrides,
	});
};
const securityLog = (count, offset = 0) => `${Array.from({ length: count }, (_, index) => securityLine(offset + index)).join("\n")}\n`;
const write = (name, content) => fs.writeFileSync(path.join(temp, name), content);
const stateRow = () => database("security_collector_state").first();
const eventCount = async () => Number((await database("security_event").count("id as count").first()).count);

before(async () => {
	// The collector imports the application's lazy database factory. Point its
	// fallback SQLite/key files at a writable temporary directory before loading
	// the module; the configured test database replaces that factory below.
	const configDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "security-collector-config-"));
	process.env.DB_SQLITE_FILE = path.join(configDirectory, "fallback.sqlite");
	process.env.NODE_ENV = "test";
	process.env.NODE_CONFIG_DIR = configDirectory;
	process.env.NSPM_KEYS_FILE = path.join(configDirectory, "keys.json");
	const module = await import("./security-events.js");
	collector = module.default;
	({ candidateFiles, configureSecurityCollectorForTesting, resetSecurityCollectorTestState, FALLBACK_HOST_ID } = module);

	database = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
	await eventsUp(database);
	await progressUp(database);
	await database.schema.createTable("setting", (table) => { table.string("id").primary(); table.text("value"); });
});
after(async () => {
	await progressDown(database);
	await eventsDown(database);
	await database.destroy();
});

beforeEach(async () => {
	temp = fs.mkdtempSync(path.join(os.tmpdir(), "security-collector-"));
	await database("security_event").del();
	await database("security_log_cursor").del();
	await database("security_collector_state").del();
	configureSecurityCollectorForTesting({ database, logDirectory: temp });
	discoverHosts = collector.discoverHosts;
	collector.discoverHosts = async () => [{ id: FALLBACK_HOST_ID, domain_names: null, owner_user_id: null }, HOST];
});
afterEach(() => {
	resetSecurityCollectorTestState();
	collector.discoverHosts = discoverHosts;
	fs.rmSync(temp, { recursive: true, force: true });
});

describe("security collector cycles", () => {
	it("ingests the current log and advances its cursor to the end of the file", async () => {
		write("proxy-host-1_security.log", securityLog(20));
		await collector.fetch();

		assert.equal(await eventCount(), 20);
		const state = await stateRow();
		assert.equal(Number(state.events_inserted), 20);
		assert.equal(Number(state.lines_read), 20);
		assert.equal(Boolean(state.limit_reached), false);
		const cursor = await database("security_log_cursor").where("log_kind", "security").first();
		assert.equal(Number(cursor.byte_offset), fs.statSync(path.join(temp, "proxy-host-1_security.log")).size);
	});

	it("makes strict forward progress across consecutive cycles", async () => {
		write("proxy-host-1_security.log", securityLog(10));
		await collector.fetch();
		const first = await eventCount();

		fs.appendFileSync(path.join(temp, "proxy-host-1_security.log"), securityLog(10, 10));
		await collector.fetch();
		const second = await eventCount();

		assert.equal(first, 10);
		assert.ok(second > first, `expected more than ${first} events, got ${second}`);
		assert.equal(second, 20);
		// A cycle with nothing new must not re-ingest, and must not regress.
		await collector.fetch();
		assert.equal(await eventCount(), 20);
	});

	it("settles a file's identity once and does not re-ingest it", async () => {
		// Root cause B: an inspection pass hashed every candidate in full on every
		// cycle. A file whose recorded fingerprint already covers its whole size is
		// identified by inode alone and never read for identification again.
		write("proxy-host-1_security.log.2.gz", gzipSync(Buffer.from(securityLog(5))));
		await collector.fetch();
		const first = await database("security_log_cursor").first();
		const size = fs.statSync(path.join(temp, "proxy-host-1_security.log.2.gz")).size;
		assert.equal(Number(first.fingerprint_size), size);

		await collector.fetch();
		assert.equal(await eventCount(), 5);
		const second = await database("security_log_cursor").first();
		assert.equal(second.content_fingerprint, first.content_fingerprint);
		assert.equal(Number(second.fingerprint_size), size);
	});

	it("reaches every host's live telemetry even behind large error logs", async () => {
		// The budget used to be consumed identifying the error logs of the hosts
		// swept first, so the later hosts' security logs were never read — and
		// because no cursor could advance, the next cycle repeated the same work.
		const hosts = Array.from({ length: 6 }, (_, index) => ({ id: index + 1, domain_names: [`host-${index + 1}.test`], owner_user_id: 3 }));
		collector.discoverHosts = async () => hosts;
		// Large in bytes — which is what identification costs — without producing
		// an event volume that would take dozens of cycles to drain.
		const noise = `2026/08/13 12:00:00 [error] 1#1: upstream timed out: ${"detail ".repeat(110)}\n`.repeat(2000);
		for (const host of hosts) {
			write(`proxy-host-${host.id}_error.log`, noise);
			write(`proxy-host-${host.id}_security.log`, securityLog(5).replaceAll('"proxy_host_id":"1"', `"proxy_host_id":"${host.id}"`));
		}

		let previous = -1;
		for (let cycle = 0; cycle < 10 && previous !== (await eventCount()); cycle += 1) {
			previous = await eventCount();
			await collector.fetch();
		}

		const security = await database("security_event").where("source_kind", "security_access").count("id as count").first();
		assert.equal(Number(security.count), hosts.length * 5, "every host's security log must be reached");
		assert.equal(Number((await stateRow()).files_pending), 0);
	});

	it("collects fallback records with no proxy host attribution", async () => {
		write("fallback_security.log", securityLog(4).replaceAll('"proxy_host_id":"1"', '"proxy_host_id":""'));
		await collector.fetch();

		const rows = await database("security_event").select("proxy_host_id", "host_domain_snapshot");
		assert.equal(rows.length, 4);
		for (const row of rows) {
			assert.equal(row.proxy_host_id, null);
			assert.equal(row.host_domain_snapshot, null);
		}
	});

	it("counts only files that exist as pending and resumes where it stopped", async () => {
		write("proxy-host-1_security.log", securityLog(3));
		await collector.fetch();

		const state = await stateRow();
		// 43 candidate slots per host, of which one exists. Phantom rotations
		// must not be reported as outstanding work.
		assert.equal(Number(state.files_pending), 0);
		assert.equal(Number(state.last_host_id), 1);
		assert.equal(Number(state.last_candidate_index), 0);
	});

	it("orders candidates newest first and gives the fallback its own slots", () => {
		const files = candidateFiles(1);
		assert.equal(files[0].path, `${temp}/proxy-host-1_security.log`);
		assert.equal(files[1].path, `${temp}/proxy-host-1_security.log.1`);
		assert.ok(files.findIndex((file) => file.kind === "security") < files.findIndex((file) => file.kind === "error"));
		const fallback = candidateFiles(FALLBACK_HOST_ID);
		assert.equal(fallback[0].path, `${temp}/fallback_security.log`);
		assert.ok(fallback.every((file) => file.kind === "security"));
	});

	it("keeps a highly compressible archive instead of rejecting it every cycle", async () => {
		// Root cause D: a repetitive log gzips far past the ratio that was tuned
		// for untrusted uploads, which discarded the file on every cycle.
		const repetitive = Buffer.from(securityLine(0).concat("\n").repeat(2000));
		write("proxy-host-1_security.log.3.gz", gzipSync(repetitive));
		assert.ok(fs.statSync(path.join(temp, "proxy-host-1_security.log.3.gz")).size * 25 < repetitive.length);

		await collector.fetch();
		// Identical lines collapse to one event by canonical id, but the cursor
		// must reach the end of the archive rather than staying at zero.
		const cursor = await database("security_log_cursor").first();
		assert.ok(cursor, "expected the archive to produce a cursor");
		assert.equal(Number(cursor.byte_offset), repetitive.length);
		assert.equal(Boolean((await stateRow()).limit_reached), false);
	});
});
