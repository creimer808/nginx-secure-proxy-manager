import moment from "moment";
import db from "../db.js";
import { groupSeriesByDay, normalizeDomain, rangeToSince, toSeriesEntry } from "../lib/dashboard-report-helpers.js";
import { dayBucket } from "../lib/nginx-access-log-parser.js";
import internalDeadHost from "./dead-host.js";
import internalProxyHost from "./proxy-host.js";
import internalRedirectionHost from "./redirection-host.js";
import internalStream from "./stream.js";

const internalReport = {
	/**
	 * @param  {Access}   access
	 * @return {Promise}
	 */
	getHostsReport: (access) => {
		return access
			.can("reports:hosts", 1)
			.then((access_data) => {
				const userId = access.token.getUserId(1);

				const promises = [
					internalProxyHost.getCount(userId, access_data.permission_visibility),
					internalRedirectionHost.getCount(userId, access_data.permission_visibility),
					internalStream.getCount(userId, access_data.permission_visibility),
					internalDeadHost.getCount(userId, access_data.permission_visibility),
				];

				return Promise.all(promises);
			})
			.then((counts) => {
				return {
					proxy: counts.shift(),
					redirection: counts.shift(),
					stream: counts.shift(),
					dead: counts.shift(),
				};
			});
	},

	/**
	 * Security & Traffic dashboard report.
	 *
	 * Authorization/visibility is enforced server-side in EVERY query: metrics are
	 * always joined to active proxy_host rows and, when the user does not have
	 * global visibility, filtered by owner_user_id. Frontend filtering is UX only.
	 *
	 * @param  {Access} access
	 * @param  {string} range One of: 24h, 7d, 30d
	 * @return {Promise<Object>}
	 */
	getDashboardReport: async (access, range) => {
		const accessData = await access.can("reports:dashboard", 1);
		const visibility = accessData.permission_visibility;
		const userId = access.token.getUserId(1);
		const since = rangeToSince(range);
		const nowEpoch = Math.floor(Date.now() / 1000);
		const num = (v) => Number(v) || 0;

		const applyVisibility = (query, ownerColumn = "owner_user_id") => {
			if (visibility !== "all") {
				query.andWhere(ownerColumn, userId);
			}
			return query;
		};

		// --- Posture: configuration counts over visible active proxy hosts. ---
		// Computed in application code to avoid database-specific conditional aggregates.
		const hostQuery = applyVisibility(
			db()("proxy_host")
				.select("enabled", "certificate_id", "ssl_forced", "block_exploits", "hsts_enabled", "access_list_id")
				.where("is_deleted", 0),
		);
		const hostRows = await hostQuery;

		let enabled = 0;
		let disabled = 0;
		let certificateConfigured = 0;
		let forcedHttps = 0;
		let effectiveHsts = 0;
		let exploitRulesEnabled = 0;
		let accessControlled = 0;

		for (const host of hostRows) {
			// Columns are read as integers via raw knex (model bool coercion is not applied).
			const isEnabled = Number(host.enabled) === 1;
			const hasCert = Number(host.certificate_id) > 0;
			const isSslForced = Number(host.ssl_forced) === 1;
			const isHsts = Number(host.hsts_enabled) === 1;

			if (isEnabled) {
				enabled += 1;
			} else {
				disabled += 1;
			}
			if (hasCert) {
				certificateConfigured += 1;
			}
			if (isSslForced) {
				forcedHttps += 1;
			}
			// Effective HSTS requires a certificate, forced HTTPS, and HSTS enabled.
			if (hasCert && isSslForced && isHsts) {
				effectiveHsts += 1;
			}
			if (Number(host.block_exploits) === 1) {
				exploitRulesEnabled += 1;
			}
			if (Number(host.access_list_id) > 0) {
				accessControlled += 1;
			}
		}

		// --- Certificate posture over certificates used by visible hosts. ---
		// Normalize driver values because SQLite returns date text while MySQL and
		// PostgreSQL may return Date objects.
		let certQuery = db()("certificate as c")
			.join("proxy_host as p", "p.certificate_id", "c.id")
			.where("p.is_deleted", 0)
			.andWhere("c.is_deleted", 0)
			.groupBy("c.id", "c.expires_on")
			.select("c.expires_on");
		certQuery = applyVisibility(certQuery, "p.owner_user_id");
		const certRows = await certQuery;

		const nowMillis = Date.now();
		const soonMillis = moment(nowMillis).add(30, "days").valueOf();
		let certificatesExpired = 0;
		let certificatesExpiring = 0;
		for (const row of certRows) {
			const expiresMillis = moment(row.expires_on).valueOf();
			if (!Number.isFinite(expiresMillis)) {
				continue;
			}
			if (expiresMillis < nowMillis) {
				certificatesExpired += 1;
			} else if (expiresMillis < soonMillis) {
				certificatesExpiring += 1;
			}
		}

		const posture = {
			enabled,
			disabled,
			certificate_configured: certificateConfigured,
			forced_https: forcedHttps,
			effective_hsts: effectiveHsts,
			exploit_rules_enabled: exploitRulesEnabled,
			access_controlled: accessControlled,
			certificates_expired: certificatesExpired,
			certificates_expiring: certificatesExpiring,
		};

		// The kill switch suppresses historical traffic and raw-IP output while the
		// retention-only timer continues deleting stored aggregates.
		if (process.env.TRAFFIC_METRICS_ENABLED === "false") {
			return {
				range,
				generated_at: nowEpoch,
				collection: { enabled: false },
				posture,
				traffic: {
					requests: 0,
					bytes_sent: 0,
					status_1xx: 0,
					status_2xx: 0,
					status_3xx: 0,
					status_4xx: 0,
					status_5xx: 0,
				},
				series: [],
				top_hosts: [],
				top_sources: { approximate: true, items: [] },
			};
		}

		// --- Traffic totals over visible hosts within the range. ---
		const trafficBase = () =>
			db()("proxy_host_traffic_hourly as t")
				.join("proxy_host as p", "p.id", "t.proxy_host_id")
				.where("p.is_deleted", 0)
				.andWhere("t.bucket_start", ">=", since);

		let totalsQuery = trafficBase();
		totalsQuery = applyVisibility(totalsQuery, "p.owner_user_id");
		const totalsRow = await totalsQuery
			.first()
			.sum({
				requests: "t.request_count",
				bytes_sent: "t.bytes_sent",
				status_1xx: "t.status_1xx",
				status_2xx: "t.status_2xx",
				status_3xx: "t.status_3xx",
				status_4xx: "t.status_4xx",
				status_5xx: "t.status_5xx",
			});
		const traffic = {
			requests: num(totalsRow?.requests),
			bytes_sent: num(totalsRow?.bytes_sent),
			status_1xx: num(totalsRow?.status_1xx),
			status_2xx: num(totalsRow?.status_2xx),
			status_3xx: num(totalsRow?.status_3xx),
			status_4xx: num(totalsRow?.status_4xx),
			status_5xx: num(totalsRow?.status_5xx),
		};

		// --- Historical series: hourly buckets, rolled up to days for 7d/30d. ---
		let seriesQuery = trafficBase();
		seriesQuery = applyVisibility(seriesQuery, "p.owner_user_id");
		const hourlySeriesRows = await seriesQuery
			.select("t.bucket_start")
			.sum({
				request_count: "t.request_count",
				status_1xx: "t.status_1xx",
				status_2xx: "t.status_2xx",
				status_3xx: "t.status_3xx",
				status_4xx: "t.status_4xx",
				status_5xx: "t.status_5xx",
			})
			.groupBy("t.bucket_start")
			.orderBy("t.bucket_start", "asc")
			.limit(720);

		const series = range === "24h" ? hourlySeriesRows.map(toSeriesEntry) : groupSeriesByDay(hourlySeriesRows);

		// --- Top proxy hosts (up to 10) by request count. ---
		let topHostsQuery = trafficBase();
		topHostsQuery = applyVisibility(topHostsQuery, "p.owner_user_id");
		const topHostAgg = await topHostsQuery
			.select("p.id")
			.sum({
				request_count: "t.request_count",
				bytes_sent: "t.bytes_sent",
				status_4xx: "t.status_4xx",
				status_5xx: "t.status_5xx",
			})
			.groupBy("p.id")
			.orderByRaw("SUM(t.request_count) DESC")
			.limit(10);

		const topHostIds = topHostAgg.map((r) => Number(r.id)).filter((id) => Number.isInteger(id));
		let domainById = {};
		if (topHostIds.length) {
			const domainQuery = applyVisibility(
				db()("proxy_host").select("id", "domain_names").whereIn("id", topHostIds).where("is_deleted", 0),
			);
			const domainRows = await domainQuery;
			domainById = Object.fromEntries(domainRows.map((r) => [r.id, normalizeDomain(r.domain_names)]));
		}
		const topHosts = topHostAgg.map((r) => ({
			id: Number(r.id),
			domain: domainById[r.id] || "",
			request_count: num(r.request_count),
			bytes_sent: num(r.bytes_sent),
			status_4xx: num(r.status_4xx),
			status_5xx: num(r.status_5xx),
		}));

		// --- Top observed client IPs (approximate, up to 10) over visible hosts. ---
		// Source rows are daily aggregates, so include the UTC boundary day. Exact
		// sub-day filtering is intentionally unavailable because requests are never stored.
		const sourceSince = dayBucket(since);
		const sourceBase = () =>
			db()("proxy_host_source_daily as s")
				.join("proxy_host as p", "p.id", "s.proxy_host_id")
				.where("p.is_deleted", 0)
				.andWhere("s.bucket_start", ">=", sourceSince);

		let topSourcesQuery = sourceBase();
		topSourcesQuery = applyVisibility(topSourcesQuery, "p.owner_user_id");
		const topSourceRows = await topSourcesQuery
			.select("s.client_ip", "s.proxy_host_id")
			.sum({
				status_4xx: "s.status_4xx",
				status_5xx: "s.status_5xx",
				observed_count: "s.observed_count",
			})
			.groupBy("s.client_ip", "s.proxy_host_id")
			.orderByRaw("SUM(s.observed_count) DESC")
			.limit(10);

		const sourceHostIds = [...new Set(topSourceRows.map((r) => Number(r.proxy_host_id)))].filter((id) =>
			Number.isInteger(id),
		);
		const sourceDomainById = {};
		if (sourceHostIds.length) {
			const sourceDomainQuery = applyVisibility(
				db()("proxy_host").select("id", "domain_names").whereIn("id", sourceHostIds).where("is_deleted", 0),
			);
			const sourceDomainRows = await sourceDomainQuery;
			for (const row of sourceDomainRows) {
				sourceDomainById[row.id] = normalizeDomain(row.domain_names);
			}
		}

		const topSources = {
			approximate: true,
			items: topSourceRows.map((r) => ({
				client_ip: r.client_ip,
				proxy_host_id: Number(r.proxy_host_id),
				domain: sourceDomainById[r.proxy_host_id] || "",
				status_4xx: num(r.status_4xx),
				status_5xx: num(r.status_5xx),
				observed_count: num(r.observed_count),
			})),
		};

		return {
			range,
			generated_at: nowEpoch,
			collection: {
				enabled: process.env.TRAFFIC_METRICS_ENABLED !== "false",
			},
			posture,
			traffic,
			series,
			top_hosts: topHosts,
			top_sources: topSources,
		};
	},
};

export default internalReport;
