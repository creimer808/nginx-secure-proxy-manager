import { deepStrictEqual, ok, strictEqual, throws } from "node:assert";
import { describe, it } from "node:test";
import { groupSeriesByDay, normalizeDomain, rangeToSince, toSeriesEntry, VALID_RANGES } from "./dashboard-report-helpers.js";

describe("dashboard-report-helpers", () => {
	it("maps allowlisted ranges to epoch since cutoffs", () => {
		const now = 1786550400;
		strictEqual(rangeToSince("24h", now), now - 86400);
		strictEqual(rangeToSince("7d", now), now - 604800);
		strictEqual(rangeToSince("30d", now), now - 2592000);
	});

	it("rejects invalid or missing ranges", () => {
		throws(() => rangeToSince("99d"), /Invalid range/);
		throws(() => rangeToSince(undefined), /Invalid range/);
		throws(() => rangeToSince(""), /Invalid range/);
	});

	it("exposes exactly the three allowlisted ranges", () => {
		deepStrictEqual(VALID_RANGES, ["24h", "7d", "30d"]);
	});

	it("rolls hourly rows up into UTC daily buckets", () => {
		const day = 1786492800; // a UTC day boundary (epoch % 86400 === 0)
		const rows = [
			{ bucket_start: day, request_count: 5, status_1xx: 0, status_2xx: 5, status_3xx: 0, status_4xx: 0, status_5xx: 0 },
			{ bucket_start: day + 3600, request_count: 7, status_1xx: 0, status_2xx: 6, status_3xx: 0, status_4xx: 1, status_5xx: 0 },
			{ bucket_start: day + 86400, request_count: 3, status_1xx: 0, status_2xx: 3, status_3xx: 0, status_4xx: 0, status_5xx: 0 },
		];
		const out = groupSeriesByDay(rows);
		strictEqual(out.length, 2);
		strictEqual(out[0].bucket_start, day);
		strictEqual(out[0].request_count, 12);
		strictEqual(out[0].status_4xx, 1);
		strictEqual(out[1].bucket_start, day + 86400);
		strictEqual(out[1].request_count, 3);
	});

	it("normalizes domain_names from json text, array and empty values", () => {
		strictEqual(normalizeDomain('["example.com","www.example.com"]'), "example.com");
		strictEqual(normalizeDomain(["a.example", "b.example"]), "a.example");
		strictEqual(normalizeDomain("not-json"), "not-json");
		strictEqual(normalizeDomain(""), "");
		strictEqual(normalizeDomain(null), "");
	});

	it("coerces series entries to safe numbers", () => {
		const entry = toSeriesEntry({
			bucket_start: "1786540800",
			request_count: undefined,
			status_1xx: null,
			status_2xx: "2",
			status_3xx: 0,
			status_4xx: 0,
			status_5xx: 0,
		});
		strictEqual(entry.bucket_start, 1786540800);
		strictEqual(entry.request_count, 0);
		strictEqual(entry.status_2xx, 2);
		ok(Number.isFinite(entry.status_1xx));
	});
});
