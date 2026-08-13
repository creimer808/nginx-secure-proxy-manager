import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { MAX_EVENT_BYTES, parseNginxErrorLine, parseSecurityAccessLine } from "./security-event-parser.js";

const context = { proxyHostId: 12, segmentId: "segment", lineOffset: 42 };
const payload = (overrides = {}) => ({
	schema_version: "1", ruleset_version: "2026-08-13", request_id: "request-1", timestamp: "2026-08-13T12:00:00.000Z", msec: "1786622400.000", 
	proxy_host_id: "12", rule_id: "sql.union-select", rule_category: "sql", rule_action: "block", event_type: "exploit_rule", severity: "high",
	remote_addr: "2001:db8::1", realip_remote_addr: "192.0.2.4", remote_port: "1234", request_method: "GET", scheme: "https", host: "example.test",
	request_uri: "/?q=quote%22%5C日本語", server_protocol: "HTTP/2.0", status: "403", upstream_status: "", request_length: "100", body_bytes_sent: "12",
	request_time: "0.125", upstream_addr: "", upstream_response_time: "", ssl_protocol: "TLSv1.3", ssl_cipher: "TLS_AES_256_GCM_SHA384", remote_user: "", http_user_agent: "evil\"\\日本語", http_referer: "https://ref.test/?x=1",
	...overrides,
});

describe("security event parser", () => {
	it("parses escaped Unicode metadata and IPv4/IPv6 fields without changing text", () => {
		const event = parseSecurityAccessLine(JSON.stringify(payload()), context);
		assert.equal(event.client_ip, "2001:db8::1");
		assert.equal(event.peer_ip, "192.0.2.4");
		assert.equal(event.request_uri, "/?q=quote%22%5C日本語");
		assert.equal(event.user_agent, "evil\"\\日本語");
		assert.equal(event.request_time_ms, 125);
		assert.equal(event.ingest_line_offset, 42);
		assert.match(event.event_id, /^[a-f0-9]{64}$/);
	});

	it("accepts absent optional upstream and TLS fields", () => {
		const event = parseSecurityAccessLine(JSON.stringify(payload({ rule_id: "", rule_category: "", rule_action: "", event_type: "http_status", severity: "low", upstream_status: undefined, ssl_protocol: undefined, ssl_cipher: undefined })), context);
		assert.equal(event.event_type, "http_status");
		assert.equal(event.rule_id, null);
		assert.equal(event.upstream_status, null);
	});

	it("rejects malformed, inconsistent, invalid-IP, and oversized input", () => {
		assert.throws(() => parseSecurityAccessLine("{", context));
		assert.throws(() => parseSecurityAccessLine(JSON.stringify(payload({ event_type: "http_status" })), context));
		assert.throws(() => parseSecurityAccessLine(JSON.stringify(payload({ remote_addr: "not-an-ip" })), context));
		assert.throws(() => parseSecurityAccessLine("x".repeat(MAX_EVENT_BYTES + 1), context));
	});

	it("parses nginx errors and retains an unparsed line as text", () => {
		const parsed = parseNginxErrorLine("2026/08/13 12:00:00 [error] 1#1: upstream failed", context);
		assert.equal(parsed.nginx_error_level, "error");
		assert.equal(parsed.severity, "high");
		const fallback = parseNginxErrorLine("malicious <message> 日本語", context);
		assert.equal(fallback.nginx_error_level, "unknown");
		assert.equal(fallback.nginx_error_message, "malicious <message> 日本語");
	});
});
