import { deepStrictEqual, ok, strictEqual } from "node:assert";
import { describe, it } from "node:test";
import { aggregateParsed, mergeAndBoundSources, retentionCutoff } from "./traffic-aggregate.js";

const line = (status, ip = "203.0.113.9", bytes = 100, host = 1, ts = 1786550400) => ({
	proxyHostId: host,
	timestamp: ts,
	status,
	bytesSent: bytes,
	clientIp: ip,
});

describe("traffic-aggregate", () => {
	it("counts status classes and totals correctly", () => {
		const { hourly } = aggregateParsed([
			line(200, "10.0.0.1", 50),
			line(204, "10.0.0.1", 5),
			line(301, "10.0.0.2", 10),
			line(403, "10.0.0.3", 20),
			line(500, "10.0.0.4", 30),
		]);

		strictEqual(hourly.size, 1);
		const entry = [...hourly.values()][0];
		strictEqual(entry.request_count, 5);
		strictEqual(entry.status_2xx, 2);
		strictEqual(entry.status_3xx, 1);
		strictEqual(entry.status_4xx, 1);
		strictEqual(entry.status_5xx, 1);
		strictEqual(entry.bytes_sent, 115);
	});

	it("separates buckets by UTC hour boundary", () => {
		const base = 1786550400; // an hour boundary
		const { hourly } = aggregateParsed([
			line(200, "10.0.0.1", 1, 1, base),
			line(200, "10.0.0.1", 1, 1, base + 3599),
			line(200, "10.0.0.1", 1, 1, base + 3600),
		]);
		strictEqual(hourly.size, 2);
		deepStrictEqual(
			[...hourly.values()].map((e) => e.request_count).sort((a, b) => a - b),
			[1, 2],
		);
	});

	it("adds multiple files into shared aggregate maps without overwriting", () => {
		const first = aggregateParsed([line(200, "10.0.0.1", 10)]);
		const second = aggregateParsed([line(404, "10.0.0.2", 20)], {
			hourly: first.hourly,
			sources: first.sources,
		});
		const entry = [...second.hourly.values()][0];
		strictEqual(entry.request_count, 2);
		strictEqual(entry.status_2xx, 1);
		strictEqual(entry.status_4xx, 1);
		strictEqual(entry.bytes_sent, 30);
	});

	it("bounds in-memory source candidates under high cardinality", () => {
		const lines = Array.from({ length: 5000 }, (_, i) => line(403, `2001:db8::${i.toString(16)}`));
		const { sources } = aggregateParsed(lines, { maxSourceCandidates: 100 });
		const candidates = [...sources.values()][0];
		ok(candidates.size <= 100);
	});

	it("excludes successful responses from the source map", () => {
		const { sources } = aggregateParsed([line(200, "10.0.0.1"), line(301, "10.0.0.1")]);
		strictEqual(sources.size, 0);
	});

	it("includes 4xx/5xx sources keyed by host and day", () => {
		const { sources } = aggregateParsed([line(403, "10.0.0.1"), line(500, "10.0.0.2")]);
		strictEqual(sources.size, 1);
		const map = [...sources.values()][0];
		strictEqual(map.get("10.0.0.1").status_4xx, 1);
		strictEqual(map.get("10.0.0.2").status_5xx, 1);
	});

	it("caps merged source rows at the partition limit", () => {
		const existing = [];
		const candidates = new Map([
			["10.0.0.1", { status_4xx: 5, status_5xx: 0, observed_count: 5 }],
			["10.0.0.2", { status_4xx: 9, status_5xx: 0, observed_count: 9 }],
			["10.0.0.3", { status_4xx: 1, status_5xx: 0, observed_count: 1 }],
			["10.0.0.4", { status_4xx: 7, status_5xx: 0, observed_count: 7 }],
		]);
		const bounded = mergeAndBoundSources(existing, candidates, 2);
		strictEqual(bounded.length, 2);
		// Highest observed counts retained; lowest dropped.
		deepStrictEqual(
			bounded.map((r) => r.client_ip),
			["10.0.0.2", "10.0.0.4"],
		);
	});

	it("merges database bigint strings with new candidates numerically", () => {
		const existing = [{ client_ip: "10.0.0.1", status_4xx: "4", status_5xx: "0", observed_count: "4" }];
		const candidates = new Map([["10.0.0.1", { status_4xx: 2, status_5xx: 0, observed_count: 2 }]]);
		const bounded = mergeAndBoundSources(existing, candidates, 10);
		strictEqual(bounded.length, 1);
		strictEqual(bounded[0].observed_count, 6);
		strictEqual(bounded[0].status_4xx, 6);
	});

	it("keeps candidate overflow bounded regardless of input cardinality", () => {
		const candidates = new Map();
		for (let i = 0; i < 5000; i++) {
			candidates.set(`10.0.0.${i}`, { status_4xx: i, status_5xx: 0, observed_count: i });
		}
		const bounded = mergeAndBoundSources([], candidates, 10);
		strictEqual(bounded.length, 10);
		// Top 10 by observed count.
		ok(bounded.every((r) => r.observed_count >= 4990));
	});

	it("computes a retention cutoff in UTC epoch seconds", () => {
		const now = 1786550400;
		strictEqual(retentionCutoff(now, 30), now - 30 * 86400);
		strictEqual(retentionCutoff(now, 0), now);
	});
});
