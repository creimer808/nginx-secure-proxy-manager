import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import knex from "knex";

let configureReportForTesting;
let getDashboardReport;
let resetReportTestState;
let database;
const hourBucket = Math.floor(Date.now() / 1000);

const access = ({ userId, visibility = "all" } = {}) => ({
	can: async () => ({ roles: ["user"], permission_visibility: visibility }),
	token: { getUserId: () => userId },
});

const insertHost = (row) => database("proxy_host").insert({
	id: row.id,
	owner_user_id: row.owner,
	is_deleted: 0,
	enabled: row.enabled ?? 1,
	certificate_id: row.certificate ?? 0,
	ssl_forced: row.sslForced ?? 0,
	hsts_enabled: row.hsts ?? 0,
	block_exploits: 0,
	access_list_id: row.accessList ?? 0,
	domain_names: JSON.stringify([row.domain]),
});

before(async () => {
	// report.js imports the application's database factory. Point its config and
	// key files at a writable temporary directory before loading the module; the
	// testing seam replaces that factory below.
	const configDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "report-config-"));
	process.env.DB_SQLITE_FILE = path.join(configDirectory, "fallback.sqlite");
	process.env.NODE_ENV = "test";
	process.env.NODE_CONFIG_DIR = configDirectory;
	process.env.NSPM_KEYS_FILE = path.join(configDirectory, "keys.json");
	const internalReport = await import("./report.js");
	({ configureReportForTesting, resetReportTestState } = internalReport);
	getDashboardReport = internalReport.default.getDashboardReport;
	database = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
	await database.schema.createTable("proxy_host", (table) => {
		table.integer("id").primary();
		table.integer("owner_user_id").notNullable();
		table.integer("is_deleted").notNullable().defaultTo(0);
		table.integer("enabled").notNullable().defaultTo(1);
		table.integer("certificate_id").notNullable().defaultTo(0);
		table.integer("ssl_forced").notNullable().defaultTo(0);
		table.integer("hsts_enabled").notNullable().defaultTo(0);
		table.integer("block_exploits").notNullable().defaultTo(0);
		table.integer("access_list_id").notNullable().defaultTo(0);
		table.json("domain_names").notNullable();
	});
	await database.schema.createTable("certificate", (table) => {
		table.integer("id").primary();
		table.dateTime("expires_on").notNullable();
		table.integer("is_deleted").notNullable().defaultTo(0);
	});
	await database.schema.createTable("proxy_host_traffic_hourly", (table) => {
		table.integer("proxy_host_id").notNullable();
		table.integer("bucket_start").notNullable();
		table.integer("request_count").notNullable().defaultTo(0);
		table.integer("status_1xx").notNullable().defaultTo(0);
		table.integer("status_2xx").notNullable().defaultTo(0);
		table.integer("status_3xx").notNullable().defaultTo(0);
		table.integer("status_4xx").notNullable().defaultTo(0);
		table.integer("status_5xx").notNullable().defaultTo(0);
		table.integer("bytes_sent").notNullable().defaultTo(0);
	});
	await database.schema.createTable("proxy_host_source_daily", (table) => {
		table.integer("proxy_host_id").notNullable();
		table.integer("bucket_start").notNullable();
		table.string("client_ip", 45).notNullable();
		table.integer("status_4xx").notNullable().defaultTo(0);
		table.integer("status_5xx").notNullable().defaultTo(0);
		table.integer("observed_count").notNullable().defaultTo(0);
	});

	await insertHost({ id: 1, owner: 10, accessList: 5, domain: "list.example.com", certificate: 11, sslForced: 1, hsts: 1 });
	await insertHost({ id: 2, owner: 10, domain: "plain.example.com" });
	await insertHost({ id: 3, owner: 20, accessList: 5, domain: "other.example.com" });
	await database("certificate").insert({ id: 11, expires_on: "2020-01-01 00:00:00", is_deleted: 0 });
	await database("proxy_host_traffic_hourly").insert([
		{ proxy_host_id: 1, bucket_start: hourBucket, request_count: 10, status_1xx: 0, status_2xx: 6, status_3xx: 0, status_4xx: 4, status_5xx: 0, bytes_sent: 1000 },
		{ proxy_host_id: 2, bucket_start: hourBucket, request_count: 3, status_1xx: 0, status_2xx: 2, status_3xx: 0, status_4xx: 0, status_5xx: 1, bytes_sent: 300 },
	]);
	await database("proxy_host_source_daily").insert([
		{ proxy_host_id: 1, bucket_start: hourBucket, client_ip: "203.0.113.7", status_4xx: 0, status_5xx: 0, observed_count: 2 },
		{ proxy_host_id: 2, bucket_start: hourBucket, client_ip: "203.0.113.8", status_4xx: 0, status_5xx: 0, observed_count: 1 },
	]);
	configureReportForTesting({ database });
});

after(async () => {
	resetReportTestState();
	await database.destroy();
});

describe("dashboard report access-list filter", () => {
	it("narrows posture, traffic, series, top hosts, and top sources to the chosen access list", async () => {
		const report = await getDashboardReport(access({ userId: 1 }), "24h", 5);
		assert.deepEqual(report.posture, {
			enabled: 2,
			disabled: 0,
			certificate_configured: 1,
			forced_https: 1,
			effective_hsts: 1,
			exploit_rules_enabled: 0,
			access_controlled: 2,
			certificates_expired: 1,
			certificates_expiring: 0,
		});
		assert.equal(report.traffic.requests, 10);
		assert.equal(report.traffic.status_4xx, 4);
		assert.equal(report.series.reduce((sum, point) => sum + point.request_count, 0), 10);
		assert.deepEqual(report.top_hosts.map((row) => row.domain), ["list.example.com"]);
		assert.deepEqual(report.top_sources.items.map((row) => row.client_ip), ["203.0.113.7"]);
	});

	it("counts every visible host when no access list is named", async () => {
		const report = await getDashboardReport(access({ userId: 1 }), "24h");
		assert.equal(report.posture.enabled, 3);
		assert.equal(report.traffic.requests, 13);
		assert.equal(report.top_hosts.length, 2);
		assert.equal(report.top_sources.items.length, 2);
	});

	it("keeps owner visibility in force underneath the access-list filter", async () => {
		const report = await getDashboardReport(access({ userId: 10, visibility: "user" }), "24h", 5);
		assert.deepEqual(report.posture.enabled, 1);
		assert.deepEqual(report.posture.access_controlled, 1);
		assert.equal(report.traffic.requests, 10);
	});

	it("rejects malformed access-list identifiers", async () => {
		for (const bad of ["abc", "0", "-1", "1.5", Number.NaN]) {
			await assert.rejects(() => getDashboardReport(access({ userId: 1 }), "24h", bad), { status: 400 });
		}
	});
});
