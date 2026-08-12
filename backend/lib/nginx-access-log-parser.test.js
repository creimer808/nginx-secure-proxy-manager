import { deepStrictEqual, notStrictEqual, ok, strictEqual } from "node:assert";
import { describe, it } from "node:test";
import { dayBucket, hourBucket, parseProxyAccessLine, parseTimestamp, statusClassKey } from "./nginx-access-log-parser.js";

const ctx = { proxyHostId: 12 };

const buildLine = (overrides = {}) => {
	// A representative proxy-format line. Fields that the parser ignores are kept
	// realistic so position-sensitive matching is exercised.
	const {
		time = "12/Aug/2026:14:03:01 +0000",
		cacheStatus = "-",
		upstreamStatus = "200",
		status = "200",
		method = "GET",
		scheme = "https",
		host = "example.com",
		requestUri = "/",
		clientIp = "203.0.113.25",
		length = "612",
		gzip = "-",
		server = "example",
		userAgent = "Mozilla/5.0",
		referer = "https://ref/",
	} = overrides;
	return `[${time}] ${cacheStatus} ${upstreamStatus} ${status} - ${method} ${scheme} ${host} "${requestUri}" [Client ${clientIp}] [Length ${length}] [Gzip ${gzip}] [Sent-to ${server}] "${userAgent}" "${referer}"`;
};

describe("nginx-access-log-parser", () => {
	it("parses a valid proxy log line", () => {
		const out = parseProxyAccessLine(buildLine(), ctx);
		ok(out, "expected a parsed result");
		strictEqual(out.proxyHostId, 12);
		strictEqual(out.status, 200);
		strictEqual(out.bytesSent, 612);
		strictEqual(out.clientIp, "203.0.113.25");
		// 12/Aug/2026:14:03:01 +0000 -> UTC epoch
		strictEqual(out.timestamp, Date.UTC(2026, 7, 12, 14, 3, 1) / 1000);
	});

	it("parses IPv4 and IPv6 client addresses", () => {
		const v4 = parseProxyAccessLine(buildLine({ clientIp: "198.51.100.7" }), ctx);
		strictEqual(v4.clientIp, "198.51.100.7");

		const v6 = parseProxyAccessLine(buildLine({ clientIp: "2001:db8::1" }), ctx);
		strictEqual(v6.clientIp, "2001:db8::1");
	});

	it("rejects malformed status codes", () => {
		strictEqual(parseProxyAccessLine(buildLine({ status: "abc" }), ctx), null);
		strictEqual(parseProxyAccessLine(buildLine({ status: "99" }), ctx), null);
		strictEqual(parseProxyAccessLine(buildLine({ status: "600" }), ctx), null);
	});

	it("rejects invalid client IPs", () => {
		strictEqual(parseProxyAccessLine(buildLine({ clientIp: "not-an-ip" }), ctx), null);
		strictEqual(parseProxyAccessLine(buildLine({ clientIp: "999.999.999.999" }), ctx), null);
	});

	it("does not return or expose the request path, query, user agent or referrer", () => {
		const line = buildLine({
			requestUri: "/secret/path?token=abc&x=1",
			userAgent: "AttackBot/1.0",
			referer: "https://evil.example/steal",
		});
		const out = parseProxyAccessLine(line, ctx);
		ok(out);
		// None of the sensitive fields should appear in the parsed object's values.
		const serialized = JSON.stringify(out);
		ok(!serialized.includes("secret"), "request path leaked into result");
		ok(!serialized.includes("token"), "query string leaked into result");
		ok(!serialized.includes("AttackBot"), "user agent leaked into result");
		ok(!serialized.includes("evil.example"), "referrer leaked into result");
	});

	it("tolerates embedded/escaped quotes in the request uri", () => {
		// nginx escapes a double quote inside the uri as \". buildLine quotes the
		// uri verbatim, so construct the raw escaped line directly.
		const raw =
			'[12/Aug/2026:14:03:01 +0000] - 200 200 - GET https example.com "/path?q=\\"value\\"" [Client 203.0.113.25] [Length 612] [Gzip -] [Sent-to example] "Mozilla/5.0" "https://ref/"';
		const out = parseProxyAccessLine(raw, ctx);
		ok(out, "escaped quotes should not break parsing");
		strictEqual(out.status, 200);
		strictEqual(out.clientIp, "203.0.113.25");
	});

	it("treats a zero / absent response length as zero bytes", () => {
		const zero = parseProxyAccessLine(buildLine({ length: "0" }), ctx);
		strictEqual(zero.bytesSent, 0);

		const dash = parseProxyAccessLine(buildLine({ length: "-" }), ctx);
		strictEqual(dash.bytesSent, 0);
	});

	it("returns null for malformed lines without exposing content", () => {
		strictEqual(parseProxyAccessLine("totally not a log line", ctx), null);
		strictEqual(parseProxyAccessLine("", ctx), null);
		strictEqual(parseProxyAccessLine(buildLine({ cacheStatus: "EXTRA TOKEN" }), ctx), null);
	});

	it("converts nginx local timestamps to UTC using the recorded offset", () => {
		// +02:00 local means UTC is two hours earlier.
		const ts = parseTimestamp("12/Aug/2026:14:03:01 +0200");
		strictEqual(ts, Date.UTC(2026, 7, 12, 12, 3, 1) / 1000);

		// -05:00 local means UTC is five hours later.
		const ts2 = parseTimestamp("12/Aug/2026:14:03:01 -0500");
		strictEqual(ts2, Date.UTC(2026, 7, 12, 19, 3, 1) / 1000);

		// Bad month / format -> null
		strictEqual(parseTimestamp("12/Xyz/2026:14:03:01 +0000"), null);
		strictEqual(parseTimestamp("not a date"), null);
	});

	it("aligns epochs to hour and day buckets", () => {
		const epoch = Date.UTC(2026, 7, 12, 14, 3, 1) / 1000;
		strictEqual(hourBucket(epoch), Date.UTC(2026, 7, 12, 14, 0, 0) / 1000);
		strictEqual(dayBucket(epoch), Date.UTC(2026, 7, 12, 0, 0, 0) / 1000);
	});

	it("maps status codes to status-class counters", () => {
		strictEqual(statusClassKey(100), "status_1xx");
		strictEqual(statusClassKey(204), "status_2xx");
		strictEqual(statusClassKey(301), "status_3xx");
		strictEqual(statusClassKey(403), "status_4xx");
		strictEqual(statusClassKey(503), "status_5xx");
		strictEqual(statusClassKey(900), null);
	});

	it("rejects oversized lines defensively", () => {
		// A line far exceeding the collector's per-line cap should still parse or
		// null cleanly without throwing; the cap itself is enforced by the collector.
		const huge = buildLine({ userAgent: "x".repeat(40_000) });
		const out = parseProxyAccessLine(huge, ctx);
		ok(out, "oversized trailing fields should not break positional parsing");
		notStrictEqual(out.status, undefined);
		deepStrictEqual(Object.keys(out).sort(), ["bytesSent", "clientIp", "proxyHostId", "status", "timestamp"]);
	});
});
