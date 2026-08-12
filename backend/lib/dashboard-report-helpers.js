import error from "./error.js";
import { dayBucket } from "./nginx-access-log-parser.js";

/**
 * Pure helpers for the Security & Traffic dashboard report.
 *
 * Kept dependency-free (no database) so they can be unit tested directly.
 */

const RANGE_SECONDS = {
	"24h": 86400,
	"7d": 604800,
	"30d": 2592000,
};

const VALID_RANGES = Object.keys(RANGE_SECONDS);

/**
 * Map an allowlisted range string to a UTC epoch "since" cutoff.
 *
 * @param   {string}  range
 * @param   {number}  [nowEpoch]  Defaults to the current time.
 * @returns {number}
 */
const rangeToSince = (range, nowEpoch = Math.floor(Date.now() / 1000)) => {
	const seconds = RANGE_SECONDS[range];
	if (seconds === undefined) {
		throw new error.ValidationError("Invalid range. Must be one of: 24h, 7d, 30d");
	}
	return nowEpoch - seconds;
};

/**
 * Normalize a raw domain_names column value (JSON text or array) to the primary
 * domain string.
 *
 * @param   {string|Array} value
 * @returns {string}
 */
const normalizeDomain = (value) => {
	if (Array.isArray(value)) {
		return value[0] || "";
	}
	if (typeof value === "string" && value.length > 0) {
		try {
			const parsed = JSON.parse(value);
			return Array.isArray(parsed) ? parsed[0] || "" : String(parsed);
		} catch {
			return value;
		}
	}
	return "";
};

const toSeriesEntry = (row) => ({
	bucket_start: Number(row.bucket_start),
	request_count: Number(row.request_count) || 0,
	status_1xx: Number(row.status_1xx) || 0,
	status_2xx: Number(row.status_2xx) || 0,
	status_3xx: Number(row.status_3xx) || 0,
	status_4xx: Number(row.status_4xx) || 0,
	status_5xx: Number(row.status_5xx) || 0,
});

/**
 * Roll hourly series rows up into UTC daily buckets in application code.
 *
 * @param   {Array<Object>} hourlyRows
 * @returns {Array<Object>}
 */
const groupSeriesByDay = (hourlyRows) => {
	const byDay = new Map();
	for (const row of hourlyRows) {
		const day = dayBucket(Number(row.bucket_start));
		let entry = byDay.get(day);
		if (!entry) {
			entry = {
				bucket_start: day,
				request_count: 0,
				status_1xx: 0,
				status_2xx: 0,
				status_3xx: 0,
				status_4xx: 0,
				status_5xx: 0,
			};
			byDay.set(day, entry);
		}
		entry.request_count += Number(row.request_count) || 0;
		entry.status_1xx += Number(row.status_1xx) || 0;
		entry.status_2xx += Number(row.status_2xx) || 0;
		entry.status_3xx += Number(row.status_3xx) || 0;
		entry.status_4xx += Number(row.status_4xx) || 0;
		entry.status_5xx += Number(row.status_5xx) || 0;
	}
	return [...byDay.values()].sort((a, b) => a.bucket_start - b.bucket_start);
};

export { RANGE_SECONDS, VALID_RANGES, rangeToSince, normalizeDomain, toSeriesEntry, groupSeriesByDay };
