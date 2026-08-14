import { createHash } from "node:crypto";
import { createMemo } from "../lib/security-memo.js";
import { SECURITY_RULES } from "../lib/security-rule-catalog.js";
import { applyVisibleEvents, rangeSince, registerSecurityCache, securityAccess, securityDatabase } from "./security-api.js";

/**
 * Behavioural findings.
 *
 * The event tables record observations: one 404, one 401, one rule match. None
 * of those is interesting on its own, which is why a page of them reads as
 * noise. What is interesting is shape — one source hitting four hundred
 * distinct paths that all 404, or sixty failed logins against a single host.
 *
 * This module computes that shape on read. There is no `security_finding`
 * table: every detector is a single GROUP BY over indexes the event table
 * already carries (`client_ip`/`status`/`event_type`/`rule_id` composites), and
 * the result is memoized for the same 30 seconds as the overview. Persisting
 * findings would add a write path, a retention policy, and a reconciliation
 * problem in exchange for nothing measurable.
 *
 * Nothing here blocks, rate-limits, or notifies. A finding is a claim that
 * something is worth a human look, with the evidence filter attached.
 */

const findingsCache = registerSecurityCache(createMemo({ ttlMs: 30_000, maxEntries: 200 }));
const findingsCacheKey = (actor, range) => JSON.stringify([actor.admin, actor.visibility, actor.userId, range]);

/** Nginx error-log records are operational; every detector but the error spike ignores them. */
const OPERATIONAL_EVENT_TYPE = "nginx_error";
/** No page can act on hundreds of findings, and an unbounded list is a denial of service on the browser. */
const MAX_FINDINGS_PER_TYPE = 20;
const MAX_FINDINGS = 60;
const HOUR_MS = 3600000;

/**
 * Thresholds are the point at which a pattern stops being explainable by an
 * ordinary client. They are deliberately conservative: a missed finding costs
 * an operator nothing, a false one costs their trust in the page. Tune here,
 * in one place, rather than inside the queries.
 */
const THRESHOLDS = {
	pathScanningUris: 15,
	bruteForceAttempts: 20,
	campaignRules: 3,
	forcedBrowsing: 25,
	rateLimited: 20,
	// A tool that announces itself is worth reporting on a single request, so the
	// reporting floor and the severity unit are separate numbers here.
	scannerEvents: 1,
	scannerVolume: 5,
	errorSpikePerHour: 20,
	/** How many times its own hourly baseline a host's 5xx rate must reach. */
	errorSpikeMultiple: 3,
};

const SCANNER_RULE_IDS = SECURITY_RULES.filter((rule) => rule.category === "scanner").map((rule) => rule.id);

const SEVERITIES = ["low", "medium", "high", "critical"];
/**
 * Severity is derived from how far past the threshold a finding sits, not
 * mapped statically from its type. Ten times the threshold is a different
 * event from barely reaching it, and only a derived severity can say so.
 */
const severityFor = (value, threshold) => (value >= threshold * 10 ? "high" : value >= threshold * 3 ? "medium" : "low");
const escalate = (severity) => SEVERITIES[Math.min(SEVERITIES.length - 1, SEVERITIES.indexOf(severity) + 1)];

/**
 * Stable across polls so the UI can key on it, and across processes so two
 * replicas agree. The range is part of the identity: the same source seen over
 * 24 hours and over 30 days is two different claims.
 */
const findingId = (type, key, range) => createHash("sha256").update([type, key, range].join("\u0000")).digest("hex").slice(0, 32);

const num = (value) => Number(value) || 0;
const nullableNumber = (value) => (value === null || value === undefined ? null : Number(value));

const build = ({ type, key, range, severity, row, subject, metrics, filter, operational = false }) => ({
	id: findingId(type, key, range),
	type,
	severity,
	operational,
	first_seen: num(row.first_seen),
	last_seen: num(row.last_seen),
	evidence_count: num(row.evidence_count),
	subject,
	metrics,
	filter,
});

const findings = async (access, range) => {
	const actor = await securityAccess(access, "security:findings");
	// Authorization and range validation stay ahead of the memo, so neither a
	// revoked permission nor a bad range can be served from it.
	const since = rangeSince(range);
	const cacheKey = findingsCacheKey(actor, range);
	const cached = findingsCache.read(cacheKey);
	if (cached) return cached;

	const db = securityDatabase();
	const until = Date.now();
	const window = { from: since, to: until };
	const base = () => applyVisibleEvents(db("security_event as e"), actor).where("e.occurred_at_ms", ">=", since).whereNot("e.event_type", OPERATIONAL_EVENT_TYPE);
	/** Every detector wants the same four aggregates; only the grouping differs. */
	const withSpan = (query) => query.count("e.id as evidence_count").min("e.occurred_at_ms as first_seen").max("e.occurred_at_ms as last_seen");
	const bySource = (query) => withSpan(query.whereNotNull("e.client_ip").select("e.client_ip").groupBy("e.client_ip")).orderBy("evidence_count", "desc").limit(MAX_FINDINGS_PER_TYPE);

	const [scanning, bruteForce, campaign, forcedBrowsing, rateLimited, scanners, errorBuckets] = await Promise.all([
		bySource(base().where("e.status", 404))
			.countDistinct("e.request_uri as distinct_uris")
			.countDistinct("e.proxy_host_id as distinct_hosts")
			.havingRaw("count(distinct e.request_uri) >= ?", [THRESHOLDS.pathScanningUris]),
		withSpan(
			base()
				.where("e.status", 401)
				.whereNotNull("e.client_ip")
				.whereNotNull("e.proxy_host_id")
				.select("e.client_ip", "e.proxy_host_id")
				.max("e.host_domain_snapshot as host_domain")
				.groupBy("e.client_ip", "e.proxy_host_id"),
		)
			.havingRaw("count(e.id) >= ?", [THRESHOLDS.bruteForceAttempts])
			.orderBy("evidence_count", "desc")
			.limit(MAX_FINDINGS_PER_TYPE),
		bySource(base().whereNotNull("e.rule_id"))
			.countDistinct("e.rule_id as distinct_rules")
			.havingRaw("count(distinct e.rule_id) >= ?", [THRESHOLDS.campaignRules]),
		bySource(base().where("e.status", 403)).havingRaw("count(e.id) >= ?", [THRESHOLDS.forcedBrowsing]),
		bySource(base().where("e.status", 429)).havingRaw("count(e.id) >= ?", [THRESHOLDS.rateLimited]),
		SCANNER_RULE_IDS.length
			? bySource(base().whereIn("e.rule_id", SCANNER_RULE_IDS)).countDistinct("e.rule_id as distinct_rules").havingRaw("count(e.id) >= ?", [THRESHOLDS.scannerEvents])
			: [],
		// The spike detector needs the per-hour shape, not a single total, so it
		// is the one query that aggregates twice: buckets here, baseline in JS.
		withSpan(
			applyVisibleEvents(db("security_event as e"), actor)
				.where("e.occurred_at_ms", ">=", since)
				.where("e.status", ">=", 500)
				.whereNotNull("e.proxy_host_id")
				.select("e.proxy_host_id")
				.max("e.host_domain_snapshot as host_domain")
				.select(db.raw("floor(e.occurred_at_ms / ?) as bucket", [HOUR_MS]))
				.groupBy("e.proxy_host_id", "bucket"),
		),
	]);

	const results = [
		...scanning.map((row) =>
			build({
				type: "path_scanning",
				key: row.client_ip,
				range,
				severity: severityFor(num(row.distinct_uris), THRESHOLDS.pathScanningUris),
				row,
				subject: { client_ip: row.client_ip, proxy_host_id: null, host_domain: null },
				metrics: { distinct_uris: num(row.distinct_uris), distinct_hosts: num(row.distinct_hosts) },
				filter: { ...window, client_ip: row.client_ip, status: 404 },
			}),
		),
		...bruteForce.map((row) =>
			build({
				type: "credential_brute_force",
				key: `${row.client_ip}|${row.proxy_host_id}`,
				range,
				severity: severityFor(num(row.evidence_count), THRESHOLDS.bruteForceAttempts),
				row,
				subject: { client_ip: row.client_ip, proxy_host_id: nullableNumber(row.proxy_host_id), host_domain: row.host_domain || null },
				metrics: {},
				filter: { ...window, client_ip: row.client_ip, proxy_host_id: nullableNumber(row.proxy_host_id), status: 401 },
			}),
		),
		...campaign.map((row) =>
			build({
				type: "rule_match_campaign",
				key: row.client_ip,
				range,
				severity: severityFor(num(row.distinct_rules), THRESHOLDS.campaignRules),
				row,
				subject: { client_ip: row.client_ip, proxy_host_id: null, host_domain: null },
				metrics: { distinct_rules: num(row.distinct_rules) },
				filter: { ...window, client_ip: row.client_ip, event_type: "exploit_rule" },
			}),
		),
		...forcedBrowsing.map((row) =>
			build({
				type: "forced_browsing",
				key: row.client_ip,
				range,
				severity: severityFor(num(row.evidence_count), THRESHOLDS.forcedBrowsing),
				row,
				subject: { client_ip: row.client_ip, proxy_host_id: null, host_domain: null },
				metrics: {},
				filter: { ...window, client_ip: row.client_ip, status: 403 },
			}),
		),
		...rateLimited.map((row) =>
			build({
				type: "rate_limit_tripping",
				key: row.client_ip,
				range,
				severity: severityFor(num(row.evidence_count), THRESHOLDS.rateLimited),
				row,
				subject: { client_ip: row.client_ip, proxy_host_id: null, host_domain: null },
				metrics: {},
				filter: { ...window, client_ip: row.client_ip, status: 429 },
			}),
		),
		...scanners.map((row) =>
			build({
				type: "scanner_tooling",
				key: row.client_ip,
				range,
				severity: severityFor(num(row.evidence_count), THRESHOLDS.scannerVolume),
				row,
				subject: { client_ip: row.client_ip, proxy_host_id: null, host_domain: null },
				metrics: { distinct_rules: num(row.distinct_rules) },
				filter: { ...window, client_ip: row.client_ip, event_type: "exploit_rule" },
			}),
		),
		...errorSpikes(errorBuckets, { range, since, until, window }),
	];

	/**
	 * The correlation pass, and the only way `critical` is reachable: a source
	 * that trips two unrelated detectors is doing something an ordinary client
	 * never does, whatever the individual volumes were.
	 */
	const typesPerSource = new Map();
	for (const finding of results) {
		if (!finding.subject.client_ip) continue;
		const seen = typesPerSource.get(finding.subject.client_ip) || new Set();
		seen.add(finding.type);
		typesPerSource.set(finding.subject.client_ip, seen);
	}
	for (const finding of results) {
		if ((typesPerSource.get(finding.subject.client_ip)?.size ?? 0) > 1) finding.severity = escalate(finding.severity);
	}

	const rank = (finding) => SEVERITIES.indexOf(finding.severity);
	results.sort((a, b) => rank(b) - rank(a) || b.evidence_count - a.evidence_count || a.id.localeCompare(b.id));
	const report = {
		range,
		generated_at: until,
		window,
		counts: Object.fromEntries(SEVERITIES.map((severity) => [severity, results.filter((finding) => finding.severity === severity).length])),
		truncated: results.length > MAX_FINDINGS,
		findings: results.slice(0, MAX_FINDINGS),
	};
	return findingsCache.write(cacheKey, report);
};

/**
 * A host that always serves some 5xx is not news; a host whose 5xx rate jumps
 * against its own recent history is. The baseline is the mean over every whole
 * hour in the range rather than over the hours that happen to have errors,
 * because a host with a single bad hour would otherwise be its own baseline
 * and never register.
 *
 * Flagged operational: a 5xx spike is far more often a broken upstream than an
 * attack, so it must not inflate the security counts.
 */
const errorSpikes = (buckets, { range, since, until, window }) => {
	const perHost = new Map();
	for (const row of buckets) {
		const hostId = Number(row.proxy_host_id);
		const host = perHost.get(hostId) || { hostId, host_domain: row.host_domain || null, rows: [] };
		host.rows.push({ bucket: Number(row.bucket), count: num(row.evidence_count), first_seen: num(row.first_seen), last_seen: num(row.last_seen) });
		perHost.set(hostId, host);
	}
	const hoursInRange = Math.max(1, Math.round((until - since) / HOUR_MS));
	const results = [];
	for (const host of perHost.values()) {
		const peak = host.rows.reduce((best, row) => (row.count > best.count ? row : best));
		const total = host.rows.reduce((sum, row) => sum + row.count, 0);
		const baseline = (total - peak.count) / Math.max(1, hoursInRange - 1);
		if (peak.count < THRESHOLDS.errorSpikePerHour) continue;
		if (peak.count < baseline * THRESHOLDS.errorSpikeMultiple) continue;
		const multiple = baseline > 0 ? peak.count / baseline : peak.count;
		results.push(
			build({
				type: "error_spike",
				key: `${host.hostId}|${peak.bucket}`,
				range,
				severity: severityFor(multiple, THRESHOLDS.errorSpikeMultiple),
				row: { evidence_count: peak.count, first_seen: peak.first_seen, last_seen: peak.last_seen },
				subject: { client_ip: null, proxy_host_id: host.hostId, host_domain: host.host_domain },
				metrics: { baseline_per_hour: Math.round(baseline * 100) / 100, peak_per_hour: peak.count },
				filter: { ...window, proxy_host_id: host.hostId, status_class: "5xx" },
				operational: true,
			}),
		);
	}
	return results.sort((a, b) => b.evidence_count - a.evidence_count).slice(0, MAX_FINDINGS_PER_TYPE);
};

export { findings, SEVERITIES, THRESHOLDS };
