import fs from "node:fs";
import net from "node:net";
import { basename, sep } from "node:path";
import db from "../db.js";
import errs from "../lib/error.js";
import { openSecurityLog, readSecurityLog } from "../lib/security-log-reader.js";
import { RULE_IDS, RULESET_VERSION, SECURITY_RULES } from "../lib/security-rule-catalog.js";

let logDirectory = "/data/logs";
let databaseFactory = db;
const PAGE_DEFAULT = 50;
const PAGE_MAX = 200;
const RAW_LINE_LIMIT = 500;
const RAW_SCAN_BYTES = 2 * 1024 * 1024;
const RAW_COMPRESSED_INPUT_BYTES = 64 * 1024 * 1024;
const RAW_SCAN_RUNTIME_MS = 3000;
// Matches the collector. A ratio tuned for untrusted uploads truncates ordinary
// Nginx archives, which compress far past 25:1 when a scanner repeats one path.
const RAW_GZIP_EXPANSION_RATIO = 500;
const MAX_CONCURRENT_SCANS = 2;
const MAX_SCANS_PER_USER = 1;
const SCAN_WINDOW_MS = 60_000;
const MAX_SCANS_PER_WINDOW = 12;
const requestScans = new Map();
let activeScans = 0;

const eventTypes = new Set(["exploit_rule", "http_status", "nginx_error"]);
const severities = new Set(["low", "medium", "high", "critical"]);
const methods = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE"]);
const logKinds = new Set(["access", "error", "security"]);
const globalFiles = {
	access: ["fallback_http_access.log", "fallback_http_access.log.1", ...Array.from({ length: 3 }, (_, index) => `fallback_http_access.log.${index + 2}.gz`)],
	error: [
		"fallback_http_error.log",
		...Array.from({ length: 10 }, (_, index) => `fallback_http_error.log.${index + 1}.gz`),
	],
	// Traffic that never reached a proxy host. Reachable only through the global
	// target, which parseTarget already restricts to administrators.
	security: ["fallback_security.log", "fallback_security.log.1", ...Array.from({ length: 29 }, (_, index) => `fallback_security.log.${index + 2}.gz`)],
};

const isAdmin = (data) => Array.isArray(data.roles) && data.roles.includes("admin");
const escapeLike = (value) => value.replace(/[\\%_]/g, "\\$&");
const parseInteger = (value, name, min, max) => {
	if (!/^\d+$/.test(String(value))) throw new errs.ValidationError(`Invalid ${name}`);
	const n = Number(value);
	if (!Number.isSafeInteger(n) || n < min || n > max) throw new errs.ValidationError(`Invalid ${name}`);
	return n;
};
const parseTimestamp = (value, name) => {
	if (value === undefined) return null;
	const time = /^\d+$/.test(String(value)) ? Number(value) : Date.parse(String(value));
	if (!Number.isSafeInteger(time) || time < 0) throw new errs.ValidationError(`Invalid ${name}`);
	return time;
};
const decodeCursor = (value, fields) => {
	if (!value) return null;
	try {
		const data = JSON.parse(Buffer.from(value, "base64url").toString("utf8"));
		if (!fields.every((field) => Number.isSafeInteger(data[field]) && data[field] >= 0)) throw new Error();
		return data;
	} catch { throw new errs.ValidationError("Invalid cursor"); }
};
const encodeCursor = (data) => Buffer.from(JSON.stringify(data)).toString("base64url");
const normalizeEventNumbers = (row) => {
	if (!row) return row;
	for (const field of ["id", "occurred_at_ms", "proxy_host_id", "owner_user_id_snapshot", "peer_port", "status", "request_bytes", "response_bytes", "request_time_ms", "upstream_time_ms", "ingest_line_offset"]) {
		if (row[field] !== null && row[field] !== undefined) row[field] = Number(row[field]);
	}
	return row;
};

/** Shared, current-host visibility guard for every event and host-log query. */
const securityAccess = async (access, permission) => {
	const data = await access.can(permission);
	return { admin: isAdmin(data), visibility: data.permission_visibility, userId: access.token.getUserId(0) };
};
const applyVisibleEvents = (query, actor) => {
	query.leftJoin("proxy_host as p", "p.id", "e.proxy_host_id");
	if (!actor.admin) {
		query.whereNotNull("e.proxy_host_id").andWhere("p.is_deleted", 0);
		if (actor.visibility !== "all") query.andWhere("p.owner_user_id", actor.userId);
	}
	return query;
};
const authorizeHost = async (actor, hostId) => {
	const host = await databaseFactory()("proxy_host").select("id", "owner_user_id", "is_deleted").where("id", hostId).first();
	if (!host) throw new errs.ItemNotFoundError(hostId);
	// Deleted host evidence is retained for administrators only. Current user
	// visibility never grants access to an orphaned/deleted host.
	if (Number(host.is_deleted) === 1 && !actor.admin) throw new errs.ItemNotFoundError(hostId);
	if (!actor.admin && actor.visibility !== "all" && Number(host.owner_user_id) !== actor.userId) throw new errs.PermissionError();
	return host;
};
const literalSearch = (builder, column, query) => builder.whereRaw(`${column} LIKE ? ESCAPE '\\'`, [`%${escapeLike(query)}%`]);

const validateEventFilters = (input) => {
	const allowed = new Set(["from", "to", "proxy_host_id", "event_type", "severity", "rule_id", "client_ip", "status", "status_class", "method", "query", "limit", "cursor"]);
	if (Object.keys(input).some((key) => !allowed.has(key))) throw new errs.ValidationError("Invalid event filter");
	const from = parseTimestamp(input.from, "from") ?? Date.now() - 24 * 60 * 60 * 1000;
	const to = parseTimestamp(input.to, "to") ?? Date.now();
	if (to < from || to - from > 366 * 86400 * 1000) throw new errs.ValidationError("Invalid time range");
	const query = input.query === undefined ? null : String(input.query);
	if (query !== null && (query.length < 1 || query.length > 256 || to - from > 24 * 60 * 60 * 1000)) throw new errs.ValidationError("Text search requires a maximum 24 hour range");
	const enumFilter = (name, values) => input[name] === undefined ? null : (values.has(String(input[name])) ? String(input[name]) : (() => { throw new errs.ValidationError(`Invalid ${name}`); })());
	const status = input.status === undefined ? null : parseInteger(input.status, "status", 100, 599);
	const statusClass = input.status_class === undefined ? null : String(input.status_class);
	if (statusClass !== null && statusClass !== "5xx") throw new errs.ValidationError("Invalid status_class");
	if (status !== null && statusClass !== null) throw new errs.ValidationError("Status and status_class cannot be combined");
	const hostId = input.proxy_host_id === undefined ? null : parseInteger(input.proxy_host_id, "proxy_host_id", 1, Number.MAX_SAFE_INTEGER);
	const clientIp = input.client_ip === undefined ? null : String(input.client_ip);
	if (clientIp && net.isIP(clientIp) === 0) throw new errs.ValidationError("Invalid client_ip");
	const ruleId = input.rule_id === undefined ? null : String(input.rule_id);
	if (ruleId && (!RULE_IDS.has(ruleId) || ruleId.length > 128)) throw new errs.ValidationError("Invalid rule_id");
	return { from, to, query, status, statusClass, hostId, clientIp, ruleId, eventType: enumFilter("event_type", eventTypes), severity: enumFilter("severity", severities), method: enumFilter("method", methods), limit: input.limit === undefined ? PAGE_DEFAULT : parseInteger(input.limit, "limit", 1, PAGE_MAX), cursor: decodeCursor(input.cursor, ["t", "i"]) };
};

const listEvents = async (access, input) => {
	const actor = await securityAccess(access, "security:events-list");
	const f = validateEventFilters(input);
	if (f.hostId) await authorizeHost(actor, f.hostId);
	const query = applyVisibleEvents(databaseFactory()("security_event as e"), actor)
		.select("e.id", "e.event_id", "e.occurred_at_ms", "e.proxy_host_id", "e.event_type", "e.severity", "e.rule_id", "e.client_ip", "e.method", "e.request_uri", "e.status", "e.request_time_ms", "e.host_domain_snapshot")
		.whereBetween("e.occurred_at_ms", [f.from, f.to]);
	if (f.hostId) query.andWhere("e.proxy_host_id", f.hostId);
	if (f.eventType) query.andWhere("e.event_type", f.eventType);
	if (f.severity) query.andWhere("e.severity", f.severity);
	if (f.ruleId) query.andWhere("e.rule_id", f.ruleId);
	if (f.clientIp) query.andWhere("e.client_ip", f.clientIp);
	if (f.status) query.andWhere("e.status", f.status);
	if (f.statusClass === "5xx") query.whereBetween("e.status", [500, 599]);
	if (f.method) query.andWhere("e.method", f.method);
	if (f.query) query.andWhere((q) => literalSearch(q, "e.request_uri", f.query).orWhere((or) => literalSearch(or, "e.user_agent", f.query)).orWhere((or) => literalSearch(or, "e.referrer", f.query)));
	if (f.cursor) query.andWhere((q) => q.where("e.occurred_at_ms", "<", f.cursor.t).orWhere((same) => same.where("e.occurred_at_ms", f.cursor.t).andWhere("e.id", "<", f.cursor.i)));
	const rows = await query.orderBy("e.occurred_at_ms", "desc").orderBy("e.id", "desc").limit(f.limit + 1);
	const items = rows.slice(0, f.limit).map(normalizeEventNumbers);
	return { items, next_cursor: rows.length > f.limit ? encodeCursor({ t: Number(items.at(-1).occurred_at_ms), i: Number(items.at(-1).id) }) : null };
};

const getEvent = async (access, eventId) => {
	if (!/^[A-Za-z0-9_-]{16,128}$/.test(eventId)) throw new errs.ValidationError("Invalid event id");
	const actor = await securityAccess(access, "security:events-get");
	const row = await applyVisibleEvents(databaseFactory()("security_event as e"), actor).select("e.*").where("e.event_id", eventId).first();
	if (!row) throw new errs.ItemNotFoundError(eventId);
	return normalizeEventNumbers(row);
};

const rangeSince = (range) => {
	if (!["24h", "7d", "30d"].includes(range)) throw new errs.ValidationError("Invalid range");
	return Date.now() - ({ "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000 }[range]);
};
const visibleBase = (actor, since) => applyVisibleEvents(databaseFactory()("security_event as e"), actor).where("e.occurred_at_ms", ">=", since);
const top = async (query, fields, order = "count") => (await query.select(fields).count("e.id as count").groupBy(fields).orderBy(order, "desc").limit(10)).map((row) => ({ ...row, count: Number(row.count) }));
const overview = async (access, range) => {
	const actor = await securityAccess(access, "security:overview");
	const since = rangeSince(range);
	const totals = await visibleBase(actor, since).first().count("e.id as total_events").sum({ exploit_rule_matches: databaseFactory().raw("case when e.event_type = 'exploit_rule' then 1 else 0 end"), nginx_errors: databaseFactory().raw("case when e.event_type = 'nginx_error' then 1 else 0 end"), status_401: databaseFactory().raw("case when e.status = 401 then 1 else 0 end"), status_403: databaseFactory().raw("case when e.status = 403 then 1 else 0 end"), status_404: databaseFactory().raw("case when e.status = 404 then 1 else 0 end"), status_429: databaseFactory().raw("case when e.status = 429 then 1 else 0 end"), status_5xx: databaseFactory().raw("case when e.status >= 500 then 1 else 0 end") });
	const base = () => visibleBase(actor, since);
	const [timeline, topRules, topSources, topHosts, topStatuses, topMethods, newest] = await Promise.all([
		base().select("e.event_type", "e.severity").select(databaseFactory().raw("floor(e.occurred_at_ms / 3600000) * 3600000 as bucket_start")).count("e.id as count").groupBy("bucket_start", "e.event_type", "e.severity").orderBy("bucket_start", "asc"),
		top(base().whereNotNull("e.rule_id"), ["e.rule_id"]), top(base().whereNotNull("e.client_ip"), ["e.client_ip"]), top(base().whereNotNull("e.proxy_host_id"), ["e.proxy_host_id"]), top(base().whereNotNull("e.status"), ["e.status"]), top(base().whereNotNull("e.method"), ["e.method"]), base().max("e.occurred_at_ms as occurred_at_ms").first(),
	]);
	const num = (value) => Number(value) || 0;
	const collector = actor.admin
		? { ...(await databaseFactory()("security_collector_state").first() || { available: false }), enabled: process.env.SECURITY_EVENTS_ENABLED !== "false" }
		: { available: Boolean(newest?.occurred_at_ms), lag_ms: newest?.occurred_at_ms ? Math.max(0, Date.now() - Number(newest.occurred_at_ms)) : null };
	return { range, total_events: num(totals?.total_events), exploit_rule_matches: num(totals?.exploit_rule_matches), nginx_errors: num(totals?.nginx_errors), statuses: { "401": num(totals?.status_401), "403": num(totals?.status_403), "404": num(totals?.status_404), "429": num(totals?.status_429), "5xx": num(totals?.status_5xx) }, timeline: timeline.map((item) => ({ ...item, bucket_start: Number(item.bucket_start), count: num(item.count) })), top_rules: topRules, top_sources: topSources, top_hosts: topHosts, top_statuses: topStatuses, top_methods: topMethods, collector };
};
const rules = async (access, range) => {
	const actor = await securityAccess(access, "security:rules");
	const rows = await visibleBase(actor, rangeSince(range)).whereNotNull("e.rule_id").select("e.rule_id").count("e.id as count").groupBy("e.rule_id");
	const counts = new Map(rows.map((row) => [row.rule_id, Number(row.count)]));
	return SECURITY_RULES.map((rule) => ({ ...rule, ruleset_version: RULESET_VERSION, count: counts.get(rule.id) || 0 }));
};

const rotationNames = (hostId, kind) => {
	const suffix = kind === "security" ? "_security.log" : kind === "error" ? "_error.log" : "_access.log";
	const max = kind === "security" ? 30 : kind === "error" ? 10 : 4;
	return [`proxy-host-${hostId}${suffix}`, ...Array.from({ length: max }, (_, index) => [`proxy-host-${hostId}${suffix}.${index + 1}`, `proxy-host-${hostId}${suffix}.${index + 1}.gz`]).flat()];
};
const filesForTarget = (target, hostId, kind) => target === "global" ? globalFiles[kind] || [] : rotationNames(hostId, kind);
const safeLogFile = (name) => {
	if (basename(name) !== name) return null;
	try {
		const root = fs.realpathSync(logDirectory);
		const full = `${root}${sep}${name}`;
		const stat = fs.lstatSync(full);
		if (stat.isSymbolicLink() || !stat.isFile() || stat.nlink !== 1) return null;
		return full;
	} catch { return null; }
};
const parseTarget = async (actor, input) => {
	const target = input.target === undefined ? "host" : String(input.target);
	if (target === "global") {
		if (!actor.admin) throw new errs.PermissionError();
		return { target, hostId: null };
	}
	if (target !== "host") throw new errs.ValidationError("Invalid log target");
	const hostId = parseInteger(input.proxy_host_id, "proxy_host_id", 1, Number.MAX_SAFE_INTEGER);
	await authorizeHost(actor, hostId);
	return { target, hostId };
};
const listLogFiles = async (access, input) => {
	if (!logKinds.has(input.kind)) throw new errs.ValidationError("Invalid log kind");
	const actor = await securityAccess(access, "security:logs-list");
	const target = await parseTarget(actor, input);
	return filesForTarget(target.target, target.hostId, input.kind).map((name, index) => ({ rotation: index === 0 ? "current" : name.slice(name.indexOf(".log") + 4), compressed: name.endsWith(".gz"), available: Boolean(safeLogFile(name)) })).filter((file) => file.available);
};
const acquireScan = (userId) => {
	const now = Date.now();
	const state = requestScans.get(userId) || { active: 0, times: [] };
	state.times = state.times.filter((time) => now - time < SCAN_WINDOW_MS);
	if (state.active >= MAX_SCANS_PER_USER || activeScans >= MAX_CONCURRENT_SCANS || state.times.length >= MAX_SCANS_PER_WINDOW) {
		const error = new errs.ValidationError("Log viewer capacity exhausted"); error.status = 429; throw error;
	}
	state.active += 1; state.times.push(now); requestScans.set(userId, state); activeScans += 1;
	return () => { activeScans -= 1; state.active = Math.max(0, state.active - 1); if (!state.active && !state.times.length) requestScans.delete(userId); };
};
const rawCursor = (offset) => encodeCursor({ o: Math.max(0, offset) });

const readLog = async (access, input, aborted = () => false) => {
	const allowed = new Set(["target", "proxy_host_id", "kind", "rotation", "cursor", "limit", "query", "direction"]);
	if (Object.keys(input).some((key) => !allowed.has(key))) throw new errs.ValidationError("Invalid log filter");
	if (!logKinds.has(input.kind)) throw new errs.ValidationError("Invalid log kind");
	const actor = await securityAccess(access, "security:logs-read");
	const target = await parseTarget(actor, input);
	const rotation = input.rotation === undefined ? "current" : String(input.rotation);
	const names = filesForTarget(target.target, target.hostId, input.kind);
	const name = rotation === "current" ? names[0] : names.find((candidate) => candidate.slice(candidate.indexOf(".log") + 4) === rotation);
	if (!name) throw new errs.ValidationError("Invalid rotation");
	const query = input.query === undefined ? null : String(input.query);
	if (query !== null && (query.length < 1 || query.length > 256)) throw new errs.ValidationError("Invalid query");
	const limit = input.limit === undefined ? 200 : parseInteger(input.limit, "limit", 1, RAW_LINE_LIMIT);
	const direction = input.direction === undefined ? "backward" : String(input.direction);
	if (!["forward", "backward"].includes(direction)) throw new errs.ValidationError("Invalid direction");
	const file = safeLogFile(name);
	if (!file) throw new errs.ItemNotFoundError("log file");
	const cursor = decodeCursor(input.cursor, ["o"]);
	const release = acquireScan(actor.userId);
	try {
		const opened = openSecurityLog(file, logDirectory);
		try {
			// A compressed file's stat size is not a valid cursor in its decompressed
			// stream. Start gzip browsing at logical offset zero unless a caller has a
			// previously returned logical cursor; the response remains explicitly partial.
			const start = cursor ? cursor.o : direction === "backward" && !name.endsWith(".gz") ? Math.max(0, opened.stat.size - RAW_SCAN_BYTES) : 0;
			const result = await readSecurityLog(opened, { compressed: name.endsWith(".gz"), byteOffset: start, maxBytes: RAW_SCAN_BYTES, maxLineLength: 256 * 1024, maxCompressedBytes: RAW_COMPRESSED_INPUT_BYTES, maxOutputBytes: RAW_SCAN_BYTES, maxExpansionRatio: RAW_GZIP_EXPANSION_RATIO, maxRuntimeMs: RAW_SCAN_RUNTIME_MS, aborted });
			const matches = result.lines.filter((item) => !item.oversized && (!query || item.line.includes(query)));
			const selected = direction === "backward" ? matches.slice(-limit).reverse() : matches.slice(0, limit);
			// Continue from the last fully accepted record, never from scannedOffset:
			// scannedOffset may include a boundary record rejected by the page budget.
			const nextOffset = direction === "backward"
				? Math.max(0, start - RAW_SCAN_BYTES)
				: (selected.at(-1)?.endOffset ?? result.nextOffset);
			const previousOffset = direction === "backward" ? result.scannedOffset : Math.max(0, start - RAW_SCAN_BYTES);
			const lines = selected.map(({ offset, line }) => ({ offset, line }));
			const unscannedPrefix = start > 0;
			const unscannedSuffix = Boolean(result.deferred || (direction === "forward" && result.scannedOffset < opened.stat.size && !name.endsWith(".gz")) || (name.endsWith(".gz") && !cursor));
			return {
				lines,
				partial: unscannedPrefix || unscannedSuffix || matches.length > limit,
				scan_limit_bytes: RAW_SCAN_BYTES,
				// Return continuation cursors even where the current bounded window has
				// no text matches, so a search can continue without restarting.
				next_cursor: direction === "backward" ? (start > 0 ? rawCursor(nextOffset) : null) : (result.deferred || selected.length || result.scannedOffset > start ? rawCursor(nextOffset) : null),
				previous_cursor: direction === "backward" ? (result.scannedOffset > start ? rawCursor(previousOffset) : null) : (start > 0 ? rawCursor(previousOffset) : null),
			};
		} finally { fs.closeSync(opened.fd); }
	} finally { release(); }
};
/**
 * Retention plus the outcome of the startup proxy-host configuration upgrade.
 * Without the latter an operator has no way to see that Nginx never received
 * the security logging directive other than by reading container logs.
 */
const getRetention = async (access) => {
	const actor = await securityAccess(access, "security:settings-update");
	const row = await databaseFactory()("setting").where("id", "security-event-retention-days").first();
	const settings = { retention_days: Number(row?.value || 30) };
	if (!actor.admin) return settings;
	const state = await databaseFactory()("security_config_state").first();
	settings.nginx_upgrade = state
		? { last_run_on: state.last_run_on, hosts_total: Number(state.hosts_total), hosts_upgraded: Number(state.hosts_upgraded), hosts_skipped: Number(state.hosts_skipped), hosts_pending: Number(state.hosts_pending), reload_deferred: Boolean(state.reload_deferred), last_error_summary: state.last_error_summary || null }
		: null;
	return settings;
};
const updateRetention = async (access, value) => {
	const actor = await securityAccess(access, "security:settings-update");
	if (!actor.admin) throw new errs.PermissionError();
	const days = parseInteger(value, "retention_days", 7, 365);
	await databaseFactory().transaction(async (trx) => {
		const updated = await trx("setting").where("id", "security-event-retention-days").update({ value: String(days) });
		if (updated !== 1) throw new errs.ItemNotFoundError("security-event-retention-days");
		const now = new Date();
		await trx("audit_log").insert({ user_id: actor.userId, action: "security.event-retention.update", object_type: "setting", object_id: 0, meta: JSON.stringify({ retention_days: days }), created_on: now, modified_on: now });
	});
	return { retention_days: days };
};

/** Test-only seams keep database-backed authorization and filesystem tests isolated. */
const configureSecurityApiForTesting = ({ database, logDirectory: nextLogDirectory } = {}) => {
	databaseFactory = database ? () => database : db;
	if (nextLogDirectory) logDirectory = nextLogDirectory;
};
const resetSecurityApiTestState = () => {
	databaseFactory = db;
	logDirectory = "/data/logs";
	requestScans.clear();
	activeScans = 0;
};

export { applyVisibleEvents, authorizeHost, configureSecurityApiForTesting, escapeLike, getEvent, getRetention, listEvents, listLogFiles, literalSearch, overview, readLog, resetSecurityApiTestState, rules, securityAccess, updateRetention, validateEventFilters };
