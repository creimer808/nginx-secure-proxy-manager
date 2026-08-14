import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, beforeEach, describe, it } from "node:test";
import knex from "knex";
import errs from "../lib/error.js";
import { down as securityMigrationDown, up as securityMigrationUp } from "../migrations/20260813120000_security_events.js";
import { down as progressMigrationDown, up as progressMigrationUp } from "../migrations/20260814120000_security_telemetry_progress.js";

let configureSecurityApiForTesting;
let resetSecurityApiTestState;
let findings;
let THRESHOLDS;
let database;
const now = Date.now();

const access = ({ userId = 1, visibility = "user", admin = false, allowed = true } = {}) => ({
	can: async () => {
		if (!allowed) throw new errs.PermissionError();
		return { roles: admin ? ["admin"] : ["user"], permission_visibility: visibility };
	},
	token: { getUserId: () => userId },
});

let sequence = 0;
/** Every insert needs a unique event id and ingest offset; nothing else here cares what they are. */
const event = (overrides = {}) => {
	sequence += 1;
	return {
		occurred_at_ms: now,
		created_on: new Date(now),
		proxy_host_id: 1,
		source_kind: "security_access",
		event_id: `event-${String(sequence).padStart(16, "0")}`,
		event_type: "http_status",
		severity: "low",
		ingest_segment_id: "segment-1",
		ingest_line_offset: sequence,
		...overrides,
	};
};
const insert = (rows) => database("security_event").insert(rows);
const repeat = (count, factory) => Array.from({ length: count }, (_, index) => event(factory(index)));
const byType = (report, type) => report.findings.filter((finding) => finding.type === type);

before(async () => {
	const configDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "security-findings-config-"));
	process.env.DB_SQLITE_FILE = path.join(configDirectory, "fallback.sqlite");
	process.env.NODE_ENV = "test";
	process.env.NODE_CONFIG_DIR = configDirectory;
	process.env.NSPM_KEYS_FILE = path.join(configDirectory, "keys.json");
	({ configureSecurityApiForTesting, resetSecurityApiTestState } = await import("./security-api.js"));
	({ findings, THRESHOLDS } = await import("./security-findings.js"));
	database = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
	await database.schema.createTable("proxy_host", (table) => {
		table.integer("id").primary();
		table.integer("owner_user_id").notNullable();
		table.integer("is_deleted").notNullable().defaultTo(0);
	});
	await securityMigrationUp(database);
	await progressMigrationUp(database);
	await database("proxy_host").insert([
		{ id: 1, owner_user_id: 10 },
		{ id: 2, owner_user_id: 20 },
	]);
});

beforeEach(async () => {
	await database("security_event").del();
	// Each case reasons about one population, and the memo would otherwise serve
	// the previous case's answer to the same actor and range.
	configureSecurityApiForTesting({ database });
});

after(async () => {
	resetSecurityApiTestState();
	await progressMigrationDown(database);
	await securityMigrationDown(database);
	await database.destroy();
});

describe("behavioural security findings", () => {
	it("raises a path-scanning finding for distinct 404 paths and attaches a filter that reproduces the evidence", async () => {
		await insert(repeat(THRESHOLDS.pathScanningUris + 5, (index) => ({ client_ip: "203.0.113.9", status: 404, request_uri: `/probe-${index}`, occurred_at_ms: now - index * 1000 })));
		// One source repeatedly fetching the same missing page is a broken link,
		// not a scan, and must not register however many times it retries.
		await insert(repeat(60, () => ({ client_ip: "198.51.100.4", status: 404, request_uri: "/favicon.ico" })));

		const report = await findings(access({ userId: 10 }), "24h");
		const scanning = byType(report, "path_scanning");
		assert.equal(scanning.length, 1);
		assert.equal(scanning[0].subject.client_ip, "203.0.113.9");
		assert.equal(scanning[0].metrics.distinct_uris, THRESHOLDS.pathScanningUris + 5);
		assert.equal(scanning[0].evidence_count, THRESHOLDS.pathScanningUris + 5);
		assert.deepEqual({ client_ip: scanning[0].filter.client_ip, status: scanning[0].filter.status }, { client_ip: "203.0.113.9", status: 404 });
		assert.ok(scanning[0].first_seen < scanning[0].last_seen);
	});

	it("separates brute force per host, and reaches critical only when one source trips two detectors", async () => {
		await insert(repeat(THRESHOLDS.bruteForceAttempts, () => ({ client_ip: "203.0.113.10", status: 401, proxy_host_id: 1, host_domain_snapshot: "one.test" })));
		// Below the threshold against the second host: the same source is not
		// automatically credited on every host it touched.
		await insert(repeat(3, () => ({ client_ip: "203.0.113.10", status: 401, proxy_host_id: 2, host_domain_snapshot: "two.test" })));

		const single = byType(await findings(access({ userId: 1, admin: true }), "24h"), "credential_brute_force");
		assert.equal(single.length, 1);
		assert.equal(single[0].subject.proxy_host_id, 1);
		assert.equal(single[0].subject.host_domain, "one.test");
		assert.equal(single[0].severity, "low", "barely reaching the threshold is not a high-severity finding");

		// The same source now also forces browsing, far past that threshold. Two
		// unrelated detectors on one source is what makes critical reachable at all
		// -- no detector emits it on volume alone.
		await insert(repeat(THRESHOLDS.forcedBrowsing * 10, () => ({ client_ip: "203.0.113.10", status: 403, proxy_host_id: 1 })));
		configureSecurityApiForTesting({ database });
		const report = await findings(access({ userId: 1, admin: true }), "24h");
		assert.deepEqual(
			report.findings.map((finding) => [finding.type, finding.severity]),
			[
				["forced_browsing", "critical"],
				["credential_brute_force", "medium"],
			],
		);
		assert.deepEqual(report.counts, { low: 0, medium: 1, high: 0, critical: 1 });
	});

	it("attributes scanner tooling and multi-rule campaigns from the rule catalog", async () => {
		await insert([
			event({ client_ip: "203.0.113.11", event_type: "exploit_rule", rule_id: "scanner.nuclei", rule_action: "detect", status: 404 }),
			event({ client_ip: "203.0.113.11", event_type: "exploit_rule", rule_id: "path.dotenv", rule_action: "detect", status: 404 }),
			event({ client_ip: "203.0.113.11", event_type: "exploit_rule", rule_id: "path.git-config", rule_action: "detect", status: 404 }),
		]);

		const report = await findings(access({ userId: 10 }), "24h");
		const scanners = byType(report, "scanner_tooling");
		assert.equal(scanners.length, 1, "a single announced scanner request is worth reporting");
		assert.equal(scanners[0].filter.event_type, "exploit_rule");
		const campaign = byType(report, "rule_match_campaign");
		assert.equal(campaign.length, 1);
		assert.equal(campaign[0].metrics.distinct_rules, 3);
		// Both detectors fired on one source, so both escalate.
		assert.deepEqual(new Set(report.findings.map((finding) => finding.severity)), new Set(["medium"]));
	});

	it("flags a 5xx spike against the host's own baseline as operational, not as a security finding", async () => {
		const spikeHour = now - 2 * 3600000;
		await insert(repeat(THRESHOLDS.errorSpikePerHour * 3, () => ({ status: 503, proxy_host_id: 1, host_domain_snapshot: "one.test", occurred_at_ms: spikeHour })));
		// A steady trickle across other hours: the baseline the spike is measured against.
		await insert(repeat(6, (index) => ({ status: 503, proxy_host_id: 1, occurred_at_ms: now - (index + 4) * 3600000 })));
		// A second host whose errors never cluster stays quiet.
		await insert(repeat(6, (index) => ({ status: 500, proxy_host_id: 2, occurred_at_ms: now - index * 3600000 })));

		const report = await findings(access({ userId: 1, admin: true }), "24h");
		const spikes = byType(report, "error_spike");
		assert.equal(spikes.length, 1);
		assert.equal(spikes[0].subject.proxy_host_id, 1);
		assert.equal(spikes[0].operational, true);
		assert.equal(spikes[0].filter.status_class, "5xx");
		assert.ok(report.findings.every((finding) => finding.type !== "error_spike" || finding.operational));
	});

	it("keeps operational error-log records out of every behavioural detector", async () => {
		// Enough error-log rows to clear any threshold if they were ever counted.
		await insert(repeat(200, (index) => ({ event_type: "nginx_error", source_kind: "nginx_error", severity: "low", status: null, request_uri: null, client_ip: "203.0.113.12", nginx_error_message: `upstream timed out ${index}` })));
		const report = await findings(access({ userId: 10 }), "24h");
		assert.deepEqual(report.findings, []);
	});

	it("respects visibility, validates the range, and serves repeats from a short-lived memo", async () => {
		await insert(repeat(THRESHOLDS.forcedBrowsing, () => ({ client_ip: "203.0.113.13", status: 403, proxy_host_id: 2 })));

		assert.deepEqual((await findings(access({ userId: 10 }), "24h")).findings, [], "host 2 belongs to another user");
		assert.equal((await findings(access({ userId: 20 }), "24h")).findings.length, 1);
		assert.equal((await findings(access({ userId: 99, visibility: "all" }), "24h")).findings.length, 1);

		// Both the permission check and the range check settle before the memo.
		await assert.rejects(() => findings(access({ userId: 20, allowed: false }), "24h"), { status: 403 });
		await assert.rejects(() => findings(access({ userId: 20 }), "90d"), { status: 400 });

		const first = await findings(access({ userId: 20 }), "24h");
		await insert(repeat(THRESHOLDS.rateLimited, () => ({ client_ip: "203.0.113.14", status: 429, proxy_host_id: 2 })));
		const repeated = await findings(access({ userId: 20 }), "24h");
		assert.equal(repeated.findings.length, 1, "a repeat inside the TTL must not re-run the aggregates");
		assert.deepEqual(
			repeated.findings.map((finding) => finding.id),
			first.findings.map((finding) => finding.id),
			"ids must be stable across polls",
		);
	});
});
