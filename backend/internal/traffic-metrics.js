import fs from "node:fs";
import { sep } from "node:path";
import { trafficMetrics as logger } from "../logger.js";
import proxyHostModel from "../models/proxy_host.js";
import { aggregateParsed } from "../lib/traffic-aggregate.js";
import { writeAggregates } from "../lib/traffic-commit.js";
import { parseProxyAccessLine } from "../lib/nginx-access-log-parser.js";
import { readIncremental } from "../lib/log-tail.js";
import db from "../db.js";

/**
 * Background collector for the Security & Traffic dashboard.
 *
 * It reads the existing Nginx proxy access logs, aggregates only the approved
 * fields into bounded hourly and daily rows, and advances file cursors inside
 * the same transaction as the metric writes. Collection never blocks startup and
 * can be disabled with TRAFFIC_METRICS_ENABLED=false.
 */

// Limits keep collection bounded by host count and time, never by request volume.
const LOG_DIR = process.env.TRAFFIC_LOG_DIR || "/data/logs";
const MAX_TOTAL_BYTES = 25 * 1024 * 1024; // 25 MB global read budget per run
const PER_FILE_MAX_BYTES = 5 * 1024 * 1024; // 5 MB read budget per file per run
const MAX_LINE_LENGTH = 16 * 1024; // skip pathological lines
const SOURCE_MAX_PER_PARTITION = 10; // top observed client IPs per host/day
const SOURCE_CANDIDATE_LIMIT = 100; // bounded approximate candidates per host/day in memory
const RETENTION_DAYS = 30;
const MAX_RUNTIME_MS = 5000; // stop scheduling more files past this budget

const isEnabled = () => process.env.TRAFFIC_METRICS_ENABLED !== "false";

const fileKeyFromStat = (stat) => `${stat.dev}:${stat.ino}`;

/**
 * Resolve whether a candidate path is a safe regular log file to read.
 * Rejects symlinks and any path that escapes the logs directory.
 *
 * @param   {string}  filePath
 * @returns {boolean}
 */
const isSafeLogFile = (filePath) => {
	try {
		const lstat = fs.lstatSync(filePath);
		if (lstat.isSymbolicLink()) {
			return false;
		}
		const stat = fs.statSync(filePath);
		if (!stat.isFile()) {
			return false;
		}
		const resolved = fs.realpathSync(filePath);
		const logDirResolved = fs.realpathSync(LOG_DIR);
		if (resolved !== logDirResolved && !resolved.startsWith(`${logDirResolved}${sep}`)) {
			return false;
		}
		return true;
	} catch {
		return false;
	}
};

const internalTrafficMetrics = {
	intervalTimeout: 1000 * 60, // every 60 seconds
	interval: null,
	running: false,
	lastRetentionDay: null,

	initTimer: () => {
		if (isEnabled()) {
			logger.info("Traffic Metrics Timer initialized");
		} else {
			logger.info("Traffic metrics ingestion is disabled; retention cleanup remains active");
		}
		internalTrafficMetrics.interval = setInterval(internalTrafficMetrics.fetch, internalTrafficMetrics.intervalTimeout);
		// Run once immediately so data appears without waiting for the first tick.
		internalTrafficMetrics.fetch();
	},

	/**
	 * One collection cycle. Guarded so overlapping runs cannot happen.
	 *
	 * @returns {Promise<void>}
	 */
	fetch: async () => {
		if (internalTrafficMetrics.running) {
			return;
		}
		internalTrafficMetrics.running = true;

		try {
			// The kill switch stops ingestion, not privacy retention. Historical raw
			// source-IP aggregates must still be pruned on schedule.
			if (!isEnabled()) {
				await internalTrafficMetrics.commit({ hourly: new Map(), sources: new Map(), cursors: [] });
				return;
			}
			const hostIds = await internalTrafficMetrics.discoverHostIds();
			const startedAt = Date.now();
			let totalBytes = 0;

			const hourlyAgg = new Map();
			const sourceAgg = new Map();
			const cursors = [];

			for (const hostId of hostIds) {
				if (Date.now() - startedAt > MAX_RUNTIME_MS) {
					logger.warn("Traffic metrics runtime budget reached; remaining files deferred to next cycle");
					break;
				}

				for (const suffix of ["", ".1"]) {
					const filePath = `${LOG_DIR}/proxy-host-${hostId}_access.log${suffix}`;
					if (!isSafeLogFile(filePath)) {
						continue;
					}

					let stat;
					try {
						stat = fs.statSync(filePath);
					} catch {
						continue;
					}
					const fileKey = fileKeyFromStat(stat);

					// Resolve the persisted offset for this inode; missing means a new file.
					let byteOffset = 0;
					try {
						const cursorRow = await db()("traffic_log_cursor").where("file_key", fileKey).first();
						if (cursorRow) {
							byteOffset = Number(cursorRow.byte_offset) || 0;
						}
					} catch (err) {
						logger.warn(`Cursor lookup failed for ${filePath}: ${err.message}`);
						continue;
					}

					const remaining = Math.max(0, MAX_TOTAL_BYTES - totalBytes);
					if (remaining <= 0) {
						logger.warn("Traffic metrics byte budget reached; remaining files deferred to next cycle");
						break;
					}
					const maxBytes = Math.min(PER_FILE_MAX_BYTES, remaining);

					let read;
					try {
						read = readIncremental({ filePath, byteOffset, maxBytes, maxLineLength: MAX_LINE_LENGTH });
					} catch (err) {
						logger.warn(`Failed to read ${filePath}: ${err.message}`);
						continue;
					}
					if (read.fileKey !== fileKey) {
						// The file rotated between discovery and opening. Defer it rather than
						// associate bytes with the wrong inode cursor.
						logger.warn(`Log file rotated while reading ${filePath}; deferring to next cycle`);
						continue;
					}
					try {
						// Verify the pathname still refers to the same inode after the read.
						if (fileKeyFromStat(fs.statSync(filePath)) !== fileKey) {
							logger.warn(`Log file rotated after reading ${filePath}; deferring to next cycle`);
							continue;
						}
					} catch (err) {
						logger.warn(`Failed to verify ${filePath}: ${err.message}`);
						continue;
					}
					totalBytes += read.bytesConsumed;

					if (read.lines.length === 0) {
						// Still persist a cursor advance if the file shrank (truncation reset).
						if (read.newByteOffset !== byteOffset || read.truncated) {
							cursors.push({ fileKey, filePath, newByteOffset: read.newByteOffset });
						}
						continue;
					}

					for (const rawLine of read.lines) {
						if (Buffer.byteLength(rawLine, "utf8") > MAX_LINE_LENGTH) {
							continue;
						}
						const result = parseProxyAccessLine(rawLine, { proxyHostId: hostId });
						if (result) {
							aggregateParsed([result], {
								hourly: hourlyAgg,
								sources: sourceAgg,
								maxSourceCandidates: SOURCE_CANDIDATE_LIMIT,
							});
						}
					}

					cursors.push({ fileKey, filePath, newByteOffset: read.newByteOffset });
				}
			}

			// Commit even when no hosts are active so strict retention still runs.
			await internalTrafficMetrics.commit({ hourly: hourlyAgg, sources: sourceAgg, cursors });
		} catch (err) {
			// Never let the collector take down the API process.
			logger.error(`Traffic metrics collection failed: ${err.message}`);
		} finally {
			internalTrafficMetrics.running = false;
		}
	},

	/**
	 * Active (non-deleted) proxy host ids. Only these logs are ever read.
	 *
	 * @returns {Promise<number[]>}
	 */
	discoverHostIds: async () => {
		try {
			const rows = await proxyHostModel.query().select("id").where("is_deleted", 0);
			return rows.map((r) => r.id).filter((id) => Number.isInteger(id));
		} catch (err) {
			logger.warn(`Could not load proxy host ids: ${err.message}`);
			return [];
		}
	},

	/**
	 * Persist aggregated rows and advance cursors in a single short transaction.
	 * If anything throws, the transaction rolls back and no cursor advances.
	 *
	 * @param {{hourly:Map<string,Object>, sources:Map<string,Map>, cursors:Array<{fileKey:string,filePath:string,newByteOffset:number}>}} data
	 * @returns {Promise<void>}
	 */
	commit: async ({ hourly, sources, cursors }) => {
		const nowEpoch = Math.floor(Date.now() / 1000);
		const nowDay = Math.floor(nowEpoch / 86400);
		const runRetention = internalTrafficMetrics.lastRetentionDay !== nowDay;

		await db().transaction(async (trx) => {
			await writeAggregates(
				trx,
				{ hourly, sources, cursors },
				{
					runRetention,
					nowEpoch,
					retentionDays: RETENTION_DAYS,
					cursorGraceDays: RETENTION_DAYS,
					sourceMax: SOURCE_MAX_PER_PARTITION,
				},
			);
		});
		if (runRetention) {
			internalTrafficMetrics.lastRetentionDay = nowDay;
		}
	},

	// Exposed for unit tests / operational checks.
	constants: {
		LOG_DIR,
		MAX_TOTAL_BYTES,
		PER_FILE_MAX_BYTES,
		MAX_LINE_LENGTH,
		SOURCE_MAX_PER_PARTITION,
		SOURCE_CANDIDATE_LIMIT,
		RETENTION_DAYS,
		MAX_RUNTIME_MS,
	},
};

export default internalTrafficMetrics;
