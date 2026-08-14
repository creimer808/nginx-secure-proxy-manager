import crypto from "node:crypto";
import net from "node:net";
import { RULE_ID_PREFIXES } from "./security-rule-catalog.js";

const MAX_EVENT_BYTES = 256 * 1024;
const SECURITY_SCHEMA_VERSION = "1";
const EVENT_TYPES = new Set(["exploit_rule", "http_status"]);
const SEVERITIES = new Set(["low", "medium", "high", "critical"]);
const METHOD_PATTERN = /^[!#$%&'*+.^_`|~0-9A-Z-]{1,32}$/;
const OBSERVATION_STATUSES = new Set([401, 403, 404, 429]);
const RULE_ID = new RegExp(`^(?:${RULE_ID_PREFIXES.join("|")})\\.[a-z0-9-]+$`);

const asString = (value, name, { required = false, max = 65535 } = {}) => {
	if (value === undefined || value === null || value === "") {
		if (required) throw new Error(`Missing ${name}`);
		return null;
	}
	if (typeof value !== "string" || Buffer.byteLength(value, "utf8") > max) throw new Error(`Invalid ${name}`);
	return value;
};
const asInteger = (value, name, { required = false, minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) => {
	if (value === undefined || value === null || value === "") {
		if (required) throw new Error(`Missing ${name}`);
		return null;
	}
	if (!/^(?:0|[1-9]\d*)$/.test(String(value))) throw new Error(`Invalid ${name}`);
	const result = Number(value);
	if (!Number.isSafeInteger(result) || result < minimum || result > maximum) throw new Error(`Invalid ${name}`);
	return result;
};
const asDurationMs = (value, name) => {
	if (value === undefined || value === null || value === "" || value === "-") return null;
	const values = String(value).split(/[,:]\s*/).filter((item) => item && item !== "-").map(Number);
	if (!values.length || values.some((seconds) => !Number.isFinite(seconds) || seconds < 0 || seconds > 86400)) throw new Error(`Invalid ${name}`);
	return Math.round(values.reduce((sum, seconds) => sum + seconds, 0) * 1000);
};
const asIp = (value, name) => {
	const ip = asString(value, name, { max: 45 });
	if (ip && net.isIP(ip) === 0) throw new Error(`Invalid ${name}`);
	return ip;
};
const occurredAtMs = (timestamp, msec) => {
	if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?(?:[+-]\d{2}:\d{2}|Z)$/.test(timestamp)) throw new Error("Invalid timestamp");
	const parsed = Date.parse(timestamp);
	if (!Number.isFinite(parsed)) throw new Error("Invalid timestamp");
	if (msec === undefined || msec === null || msec === "") return parsed;
	if (!/^\d+\.\d{1,3}$/.test(String(msec))) throw new Error("Invalid msec");
	const milliseconds = Math.round(Number(msec) * 1000);
	if (!Number.isSafeInteger(milliseconds) || Math.abs(parsed - milliseconds) > 1000) throw new Error("Inconsistent timestamp");
	return milliseconds;
};
const canonicalEventId = (requestId, event) => crypto.createHash("sha256")
	.update(`${requestId || ""}\u0000${event.occurred_at_ms}\u0000${event.proxy_host_id}\u0000${event.rule_id || ""}\u0000${event.status || ""}\u0000${event.ingest_segment_id}\u0000${event.ingest_line_offset}`)
	.digest("hex");

const parseSecurityAccessLine = (line, context) => {
	if (Buffer.byteLength(line, "utf8") > MAX_EVENT_BYTES) throw new Error("Security event exceeds maximum size");
	let raw;
	try { raw = JSON.parse(line); } catch { throw new Error("Malformed security JSON"); }
	if (!raw || Array.isArray(raw) || typeof raw !== "object") throw new Error("Invalid security JSON");
	if (asString(raw.schema_version, "schema_version", { required: true, max: 16 }) !== SECURITY_SCHEMA_VERSION) throw new Error("Unsupported security schema version");
	// A null context host is the fallback/default server: those requests never
	// reached a proxy host, so the line carries no id and neither does the event.
	const proxyHostId = asInteger(raw.proxy_host_id, "proxy_host_id", { required: context.proxyHostId !== null, minimum: 1 });
	if (proxyHostId !== context.proxyHostId) throw new Error("Security event proxy host mismatch");
	const ruleId = asString(raw.rule_id, "rule_id", { max: 128 });
	const type = asString(raw.event_type, "event_type", { required: true, max: 32 });
	const severity = asString(raw.severity, "severity", { required: true, max: 16 });
	const status = asInteger(raw.status, "status", { required: true, minimum: 100, maximum: 599 });
	if (!EVENT_TYPES.has(type) || !SEVERITIES.has(severity)) throw new Error("Invalid event type or severity");
	if (type === "exploit_rule") {
		if (!ruleId || !RULE_ID.test(ruleId) || raw.rule_action !== "block" || status !== 403 || severity !== "high") throw new Error("Invalid exploit attribution");
	} else if (ruleId || raw.rule_category || raw.rule_action || !(OBSERVATION_STATUSES.has(status) || status >= 500)) {
		throw new Error("Invalid status observation");
	}
	const method = asString(raw.request_method, "request_method", { required: true, max: 32 });
	if (!METHOD_PATTERN.test(method)) throw new Error("Invalid request method");
	const requestId = asString(raw.request_id, "request_id", { max: 128 });
	const parsed = {
		occurred_at_ms: occurredAtMs(asString(raw.timestamp, "timestamp", { required: true, max: 64 }), raw.msec), proxy_host_id: proxyHostId,
		source_kind: "security_access", schema_version: SECURITY_SCHEMA_VERSION, ruleset_version: asString(raw.ruleset_version, "ruleset_version", { required: true, max: 64 }), request_id: requestId,
		event_type: type, severity, rule_id: ruleId, rule_category: asString(raw.rule_category, "rule_category", { max: 64 }), rule_action: asString(raw.rule_action, "rule_action", { max: 32 }),
		client_ip: asIp(raw.remote_addr, "remote_addr"), peer_ip: asIp(raw.realip_remote_addr, "realip_remote_addr"), peer_port: asInteger(raw.remote_port, "remote_port", { minimum: 1, maximum: 65535 }), method,
		scheme: asString(raw.scheme, "scheme", { max: 16 }), request_host: asString(raw.host, "host", { max: 65535 }), request_uri: asString(raw.request_uri, "request_uri", { required: true, max: MAX_EVENT_BYTES }), http_protocol: asString(raw.server_protocol, "server_protocol", { max: 16 }), status,
		upstream_status: asString(raw.upstream_status, "upstream_status", { max: 128 }), request_bytes: asInteger(raw.request_length, "request_length"), response_bytes: asInteger(raw.body_bytes_sent, "body_bytes_sent"), request_time_ms: asDurationMs(raw.request_time, "request_time"), upstream_addr: asString(raw.upstream_addr, "upstream_addr", { max: 65535 }), upstream_time_ms: asDurationMs(raw.upstream_response_time, "upstream_response_time"), tls_protocol: asString(raw.ssl_protocol, "ssl_protocol", { max: 32 }), tls_cipher: asString(raw.ssl_cipher, "ssl_cipher", { max: 65535 }), remote_user: asString(raw.remote_user, "remote_user", { max: 65535 }), user_agent: asString(raw.http_user_agent, "http_user_agent", { max: MAX_EVENT_BYTES }), referrer: asString(raw.http_referer, "http_referer", { max: MAX_EVENT_BYTES }), ingest_segment_id: context.segmentId, ingest_line_offset: context.lineOffset,
	};
	parsed.event_id = canonicalEventId(requestId, parsed);
	return parsed;
};

const parseNginxErrorLine = (line, context) => {
	if (Buffer.byteLength(line, "utf8") > MAX_EVENT_BYTES) throw new Error("Nginx error event exceeds maximum size");
	const match = /^(\d{4}\/\d{2}\/\d{2} \d{2}:\d{2}:\d{2}) \[([a-z]+)\] \d+#\d+: (.*)$/i.exec(line);
	const occurred = match ? Date.parse(match[1].replaceAll("/", "-")) : Date.now();
	const event = { occurred_at_ms: Number.isFinite(occurred) ? occurred : Date.now(), proxy_host_id: context.proxyHostId, source_kind: "nginx_error", event_type: "nginx_error", severity: match && /^(?:error|alert)$/i.test(match[2]) ? "high" : "medium", nginx_error_level: match ? match[2].toLowerCase() : "unknown", nginx_error_message: match ? match[3] : line, ingest_segment_id: context.segmentId, ingest_line_offset: context.lineOffset };
	event.event_id = canonicalEventId(null, event);
	return event;
};

export { MAX_EVENT_BYTES, parseNginxErrorLine, parseSecurityAccessLine };
