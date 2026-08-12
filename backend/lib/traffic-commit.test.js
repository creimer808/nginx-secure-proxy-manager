import { strictEqual } from "node:assert";
import knex from "knex";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { up as migrationUp } from "../migrations/20260812120000_proxy_host_traffic.js";
import { writeAggregates } from "./traffic-commit.js";

/**
 * Integration tests for writeAggregates against a real (file) SQLite database,
 * exercising the transaction body the collector relies on. These prove:
 * - hourly upserts sum across cycles (no overwrite),
 * - metrics and cursor commit atomically,
 * - a thrown transaction rolls metrics and cursor back,
 * - source partitions stay capped at the configured top-N,
 * - retention deletes only out-of-window rows.
 */

const tmpDir = () => mkdtempSync(join(tmpdir(), "npm-traffic-commit-"));

const buildDb = () => {
	const dir = tmpDir();
	const db = knex({
		client: "better-sqlite3",
		connection: { filename: `${dir}/test.sqlite` },
		useNullAsDefault: true,
		pool: { min: 0, max: 1 },
	});
	return { db, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
};

const hourlyEntry = (hostId, bucket, requestCount, status2xx = 0, bytes = 0) => ({
	proxy_host_id: hostId,
	bucket_start: bucket,
	request_count: requestCount,
	status_1xx: 0,
	status_2xx: status2xx,
	status_3xx: 0,
	status_4xx: 0,
	status_5xx: 0,
	bytes_sent: bytes,
});

const sourceMap = (entries) => {
	const m = new Map();
	for (const e of entries) {
		m.set(e.ip, { status_4xx: e.s4, status_5xx: e.s5, observed_count: e.obs });
	}
	return m;
};

describe("writeAggregates", () => {
	let db = null;
	let cleanup = null;

	before(async () => {
		const built = buildDb();
		db = built.db;
		cleanup = built.cleanup;
		await migrationUp(db);
	});

	after(async () => {
		if (db) {
			await db.destroy();
		}
		if (cleanup) {
			cleanup();
		}
	});

	const row = async (table, where) => db(table).where(where).first();

	it("sums hourly traffic across cycles instead of overwriting", async () => {
		const entry = hourlyEntry(1, 1000, 10, 10, 100);
		await db.transaction(async (trx) => {
			await writeAggregates(trx, { hourly: new Map([["1:1000", entry]]), sources: new Map(), cursors: [] }, {});
		});
		// Replay the same bucket (as would happen if it were read again) — it must add, not replace.
		await db.transaction(async (trx) => {
			await writeAggregates(trx, { hourly: new Map([["1:1000", entry]]), sources: new Map(), cursors: [] }, {});
		});
		const stored = await row("proxy_host_traffic_hourly", { proxy_host_id: 1, bucket_start: 1000 });
		strictEqual(Number(stored.request_count), 20);
		strictEqual(Number(stored.status_2xx), 20);
		strictEqual(Number(stored.bytes_sent), 200);
	});

	it("commits metrics and cursor together", async () => {
		const entry = hourlyEntry(2, 2000, 5, 5, 50);
		await db.transaction(async (trx) => {
			await writeAggregates(
				trx,
				{
					hourly: new Map([["2:2000", entry]]),
					sources: new Map(),
					cursors: [{ fileKey: "dev:2000", filePath: "/data/logs/proxy-host-2_access.log", newByteOffset: 999 }],
				},
				{},
			);
		});
		const cursor = await row("traffic_log_cursor", { file_key: "dev:2000" });
		strictEqual(Number(cursor.byte_offset), 999);
		const metric = await row("proxy_host_traffic_hourly", { proxy_host_id: 2, bucket_start: 2000 });
		strictEqual(Number(metric.request_count), 5);
	});

	it("rolls back metrics and cursor when the transaction fails", async () => {
		const before = await db("traffic_log_cursor").where("file_key", "dev:rollback").first();
		strictEqual(before, undefined);

		const entry = hourlyEntry(3, 3000, 7, 7, 70);
		let threw = false;
		try {
			await db.transaction(async (trx) => {
				await writeAggregates(
					trx,
					{
						hourly: new Map([["3:3000", entry]]),
						sources: new Map(),
						cursors: [{ fileKey: "dev:rollback", filePath: "/data/logs/proxy-host-3_access.log", newByteOffset: 5 }],
					},
					{},
				);
				// Simulate a later failure inside the same transaction.
				throw new Error("forced failure");
			});
		} catch {
			threw = true;
		}
		strictEqual(threw, true, "transaction should have thrown");

		// Nothing committed: no metric and no cursor advance.
		const metric = await row("proxy_host_traffic_hourly", { proxy_host_id: 3, bucket_start: 3000 });
		strictEqual(metric, undefined);
		const cursor = await db("traffic_log_cursor").where("file_key", "dev:rollback").first();
		strictEqual(cursor, undefined);
	});

	it("keeps source partitions capped at the configured top-N", async () => {
		const candidates = sourceMap(
			Array.from({ length: 15 }, (_, i) => ({ ip: `10.0.0.${i + 1}`, s4: i + 1, s5: 0, obs: i + 1 })),
		);
		await db.transaction(async (trx) => {
			await writeAggregates(
				trx,
				{ hourly: new Map(), sources: new Map([["4:4000", candidates]]), cursors: [] },
				{ sourceMax: 10 },
			);
		});

		const rows = await db("proxy_host_source_daily").where({ proxy_host_id: 4, bucket_start: 4000 });
		strictEqual(rows.length, 10, "partition must be capped at 10");
		// The highest-observed 10 are retained (ips 6..15).
		const observed = rows.map((r) => Number(r.observed_count)).sort((a, b) => a - b);
		strictEqual(observed[0], 6);
	});

	it("merges new source candidates with stored rows without losing history", async () => {
		const first = sourceMap([{ ip: "10.0.0.50", s4: 4, s5: 0, obs: 4 }]);
		await db.transaction(async (trx) => {
			await writeAggregates(
				trx,
				{ hourly: new Map(), sources: new Map([["5:5000", first]]), cursors: [] },
				{ sourceMax: 10 },
			);
		});
		const more = sourceMap([{ ip: "10.0.0.50", s4: 2, s5: 0, obs: 2 }]);
		await db.transaction(async (trx) => {
			await writeAggregates(
				trx,
				{ hourly: new Map(), sources: new Map([["5:5000", more]]), cursors: [] },
				{ sourceMax: 10 },
			);
		});
		const stored = await row("proxy_host_source_daily", { proxy_host_id: 5, bucket_start: 5000, client_ip: "10.0.0.50" });
		strictEqual(Number(stored.observed_count), 6);
	});

	it("deletes only out-of-window metrics and stale cursors when retention runs", async () => {
		const now = 10_000_000;
		const oldBucket = now - 31 * 86400; // older than 30 days
		const recentBucket = now - 1 * 86400;
		const old = hourlyEntry(6, oldBucket, 3, 3, 30);
		const recent = hourlyEntry(6, recentBucket, 8, 8, 80);
		await db.transaction(async (trx) => {
			await writeAggregates(
				trx,
				{ hourly: new Map([["6:old", old], ["6:recent", recent]]), sources: new Map(), cursors: [] },
				{},
			);
		});

		await db("traffic_log_cursor").insert([
			{
				file_key: "dev:stale",
				file_path: "/data/logs/stale.log",
				byte_offset: 1,
				updated_on: new Date((now - 31 * 86400) * 1000),
			},
			{
				file_key: "dev:recent",
				file_path: "/data/logs/recent.log",
				byte_offset: 2,
				updated_on: new Date((now - 1 * 86400) * 1000),
			},
		]);

		await db.transaction(async (trx) => {
			await writeAggregates(
				trx,
				{ hourly: new Map(), sources: new Map(), cursors: [] },
				{ runRetention: true, nowEpoch: now, retentionDays: 30, cursorGraceDays: 30 },
			);
		});

		const oldRow = await row("proxy_host_traffic_hourly", { proxy_host_id: 6, bucket_start: oldBucket });
		strictEqual(oldRow, undefined, "out-of-window row must be pruned");
		const recentRow = await row("proxy_host_traffic_hourly", { proxy_host_id: 6, bucket_start: recentBucket });
		strictEqual(Number(recentRow.request_count), 8, "in-window row must remain");
		strictEqual(await row("traffic_log_cursor", { file_key: "dev:stale" }), undefined);
		strictEqual(Number((await row("traffic_log_cursor", { file_key: "dev:recent" })).byte_offset), 2);
	});
});
