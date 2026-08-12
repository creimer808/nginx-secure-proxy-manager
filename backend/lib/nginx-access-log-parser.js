import net from "node:net";

/**
 * Pure parser for the Nginx Proxy Manager "proxy" access-log format.
 *
 * Format (see docker/rootfs/etc/nginx/conf.d/include/log-proxy.conf):
 *   [$time_local] $upstream_cache_status $upstream_status $status - $request_method $scheme $host "$request_uri" [Client $remote_addr] [Length $body_bytes_sent] [Gzip $gzip_ratio] [Sent-to $server] "$http_user_agent" "$http_referer"
 *
 * Security constraints enforced here:
 * - Only the timestamp, status, client IP and response bytes are extracted.
 * - The request URI, query string, user agent and referrer are matched over and
 *   then immediately discarded. They are never returned or logged.
 * - Malformed lines return null without logging their content.
 */

const MONTHS = {
	jan: 0,
	feb: 1,
	mar: 2,
	apr: 3,
	may: 4,
	jun: 5,
	jul: 6,
	aug: 7,
	sep: 8,
	oct: 9,
	nov: 10,
	dec: 11,
};

// Anchored capture of the Nginx "common log" timestamp: 12/Aug/2026:14:03:01 +0000
const TIMESTAMP_RE = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{2}):?(\d{2})$/;

// Positional line match. The request URI quoted field is skipped (not captured)
// and the trailing user-agent/referer quoted fields are ignored entirely.
// Escaped quotes inside quoted fields are tolerated via (?:[^"\\]|\\.)* .
const LINE_RE =
	/^\[([^\]]+)\]\s+\S+\s+\S+\s+(\d{3})\s+-\s+\S+\s+\S+\s+\S+\s+"(?:[^"\\]|\\.)*"\s+\[Client\s+([^\]]+)\]\s+\[Length\s+(\d+|-)\]/;

/**
 * Parse an Nginx "common log" style local timestamp into a UTC epoch second value.
 *
 * @param   {string}  value
 * @returns {number|null}
 */
const parseTimestamp = (value) => {
	const m = TIMESTAMP_RE.exec(value);
	if (!m) {
		return null;
	}

	const month = MONTHS[m[2].toLowerCase()];
	if (month === undefined) {
		return null;
	}

	const day = Number.parseInt(m[1], 10);
	const year = Number.parseInt(m[3], 10);
	const hour = Number.parseInt(m[4], 10);
	const minute = Number.parseInt(m[5], 10);
	const second = Number.parseInt(m[6], 10);
	const offsetSignHours = Number.parseInt(m[7], 10);
	const offsetMinutes = Number.parseInt(m[8], 10);

	if (
		day < 1 ||
		day > 31 ||
		hour > 23 ||
		minute > 59 ||
		second > 59
	) {
		return null;
	}

	// Build the UTC instant from the local wall-clock components, then apply the
	// recorded offset so the result is independent of the host timezone.
	const utcMillis = Date.UTC(year, month, day, hour, minute, second);
	const offsetMillis = (offsetSignHours * 60 + (offsetSignHours < 0 ? -offsetMinutes : offsetMinutes)) * 60 * 1000;
	const epochSeconds = Math.floor((utcMillis - offsetMillis) / 1000);
	if (!Number.isFinite(epochSeconds) || epochSeconds <= 0) {
		return null;
	}
	return epochSeconds;
};

/**
 * @typedef {Object} ParsedLogLine
 * @property {number}  proxyHostId  Provided by the caller from the file name.
 * @property {number}  timestamp    UTC epoch seconds.
 * @property {number}  status       HTTP status code (100-599).
 * @property {number}  bytesSent    Response bytes sent (0 when absent).
 * @property {string}  clientIp     Validated client IP.
 */

/**
 * Parse a single proxy access-log line.
 *
 * @param   {string}  line
 * @param   {{ proxyHostId: number }}  ctx
 * @returns {ParsedLogLine|null}
 */
const parseProxyAccessLine = (line, ctx) => {
	if (typeof line !== "string" || line.length === 0) {
		return null;
	}

	const m = LINE_RE.exec(line);
	if (!m) {
		// Malformed line: return null without exposing the content.
		return null;
	}

	const timestamp = parseTimestamp(m[1]);
	if (timestamp === null) {
		return null;
	}

	const status = Number.parseInt(m[2], 10);
	if (!Number.isInteger(status) || status < 100 || status > 599) {
		return null;
	}

	const clientIp = m[3].trim();
	if (net.isIP(clientIp) === 0) {
		return null;
	}

	const bytesSent = m[4] === "-" ? 0 : Number.parseInt(m[4], 10);
	if (!Number.isInteger(bytesSent) || bytesSent < 0) {
		return null;
	}

	return {
		proxyHostId: ctx.proxyHostId,
		timestamp,
		status,
		bytesSent,
		clientIp,
	};
};

/**
 * Align a UTC epoch second value down to the start of its hour.
 *
 * @param   {number}  epochSeconds
 * @returns {number}
 */
const hourBucket = (epochSeconds) => Math.floor(epochSeconds / 3600) * 3600;

/**
 * Align a UTC epoch second value down to the start of its UTC day.
 *
 * @param   {number}  epochSeconds
 * @returns {number}
 */
const dayBucket = (epochSeconds) => Math.floor(epochSeconds / 86400) * 86400;

/**
 * Map a status code to its status-class counter key.
 *
 * @param   {number}  status
 * @returns {"status_1xx"|"status_2xx"|"status_3xx"|"status_4xx"|"status_5xx"|null}
 */
const statusClassKey = (status) => {
	const clazz = Math.floor(status / 100);
	switch (clazz) {
		case 1:
			return "status_1xx";
		case 2:
			return "status_2xx";
		case 3:
			return "status_3xx";
		case 4:
			return "status_4xx";
		case 5:
			return "status_5xx";
		default:
			return null;
	}
};

export { parseProxyAccessLine, parseTimestamp, hourBucket, dayBucket, statusClassKey };
