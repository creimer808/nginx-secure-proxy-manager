import { dayBucket, hourBucket, statusClassKey } from "./nginx-access-log-parser.js";

/**
 * Pure aggregation helpers for the Security & Traffic dashboard.
 *
 * These functions operate on already-parsed log lines and plain rows so they can
 * be unit tested without a database. All in-memory maps are bounded by the number
 * of active proxy hosts, which keeps collection memory growth predictable.
 */

const STATUS_KEYS = ["status_1xx", "status_2xx", "status_3xx", "status_4xx", "status_5xx"];
const DEFAULT_SOURCE_CANDIDATE_LIMIT = 100;

const zeroHourly = (proxyHostId, bucketStart) => ({
	proxy_host_id: proxyHostId,
	bucket_start: bucketStart,
	request_count: 0,
	status_1xx: 0,
	status_2xx: 0,
	status_3xx: 0,
	status_4xx: 0,
	status_5xx: 0,
	bytes_sent: 0,
});

/**
 * Aggregate parsed lines into hourly traffic buckets and bounded daily source maps.
 *
 * Source maps only consider 4xx/5xx responses and are keyed by host/day -> ip.
 *
 * Uses a bounded Misra-Gries candidate set for source IPs. When a partition is
 * full and a new IP arrives, every candidate count is decremented and zero-count
 * candidates are removed. This preserves likely heavy hitters without retaining
 * arbitrary scanner cardinality; source rankings are therefore approximate.
 *
 * Existing maps may be supplied so multiple files can be aggregated into one
 * batch without retaining per-request objects or overwriting shared buckets.
 *
 * @param   {Array<{proxyHostId:number,timestamp:number,status:number,bytesSent:number,clientIp:string}>}  parsedLines
 * @param   {{hourly?:Map<string,Object>,sources?:Map<string,Map>,maxSourceCandidates?:number}} [options]
 * @returns {{
 *   hourly: Map<string, Object>,
 *   sources: Map<string, Map<string, {status_4xx:number,status_5xx:number,observed_count:number}>>
 * }}
 */
const aggregateParsed = (parsedLines, options = {}) => {
	const hourly = options.hourly || new Map();
	const sources = options.sources || new Map();
	const maxSourceCandidates = options.maxSourceCandidates || DEFAULT_SOURCE_CANDIDATE_LIMIT;

	for (const line of parsedLines) {
		const bucket = hourBucket(line.timestamp);
		const key = `${line.proxyHostId}:${bucket}`;
		let entry = hourly.get(key);
		if (!entry) {
			entry = zeroHourly(line.proxyHostId, bucket);
			hourly.set(key, entry);
		}
		entry.request_count += 1;
		entry.bytes_sent += line.bytesSent;
		const classKey = statusClassKey(line.status);
		if (classKey) {
			entry[classKey] += 1;
		}

		if (line.status >= 400 && line.status <= 599) {
			const dayKey = `${line.proxyHostId}:${dayBucket(line.timestamp)}`;
			let dayMap = sources.get(dayKey);
			if (!dayMap) {
				dayMap = new Map();
				sources.set(dayKey, dayMap);
			}
			let src = dayMap.get(line.clientIp);
			if (!src && dayMap.size >= maxSourceCandidates) {
				for (const [ip, candidate] of dayMap) {
					candidate.observed_count -= 1;
					if (candidate.status_5xx > 0) {
						candidate.status_5xx -= 1;
					} else if (candidate.status_4xx > 0) {
						candidate.status_4xx -= 1;
					}
					if (candidate.observed_count === 0) {
						dayMap.delete(ip);
					}
				}
				// The new observation pays for the decrement and is not retained.
				continue;
			}
			if (!src) {
				src = { status_4xx: 0, status_5xx: 0, observed_count: 0 };
				dayMap.set(line.clientIp, src);
			}
			if (line.status >= 500) {
				src.status_5xx += 1;
			} else {
				src.status_4xx += 1;
			}
			src.observed_count += 1;
		}
	}

	return { hourly, sources };
};

/**
 * Merge stored top-source rows with new candidates for a single host/day and keep
 * only the highest-observed entries. The result is capped at maxPerPartition rows.
 *
 * @param   {Array<{client_ip:string,status_4xx:number,status_5xx:number,observed_count:number}>}  existingRows
 * @param   {Map<string,{status_4xx:number,status_5xx:number,observed_count:number}>}              newCandidates
 * @param   {number}  maxPerPartition
 * @returns {Array<{client_ip:string,status_4xx:number,status_5xx:number,observed_count:number}>}
 */
const mergeAndBoundSources = (existingRows, newCandidates, maxPerPartition) => {
	const merged = new Map();

	for (const row of existingRows) {
		merged.set(row.client_ip, {
			status_4xx: Number(row.status_4xx) || 0,
			status_5xx: Number(row.status_5xx) || 0,
			observed_count: Number(row.observed_count) || 0,
		});
	}

	for (const [ip, cand] of newCandidates) {
		const cur = merged.get(ip) || { status_4xx: 0, status_5xx: 0, observed_count: 0 };
		cur.status_4xx += cand.status_4xx;
		cur.status_5xx += cand.status_5xx;
		cur.observed_count += cand.observed_count;
		merged.set(ip, cur);
	}

	// Highest observed count first; break ties by IP ascending for determinism.
	const sorted = [...merged.entries()].sort((a, b) => {
		if (b[1].observed_count !== a[1].observed_count) {
			return b[1].observed_count - a[1].observed_count;
		}
		return a[0] < b[0] ? -1 : 1;
	});

	return sorted.slice(0, maxPerPartition).map(([ip, counts]) => ({
		client_ip: ip,
		status_4xx: counts.status_4xx,
		status_5xx: counts.status_5xx,
		observed_count: counts.observed_count,
	}));
};

/**
 * Compute the UTC epoch cutoff below which rows are older than the retention window.
 *
 * @param   {number}  nowEpochSeconds
 * @param   {number}  days
 * @returns {number}
 */
const retentionCutoff = (nowEpochSeconds, days) => nowEpochSeconds - days * 86400;

export {
	DEFAULT_SOURCE_CANDIDATE_LIMIT,
	STATUS_KEYS,
	aggregateParsed,
	mergeAndBoundSources,
	retentionCutoff,
	zeroHourly,
};
