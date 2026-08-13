import fs from "node:fs";
import { basename } from "node:path";
import db from "../db.js";
import { databaseStorageBytes } from "../lib/security-database-size.js";
import { writeSecurityEvents } from "../lib/security-event-commit.js";
import { openSecurityLog, readSecurityLog } from "../lib/security-log-reader.js";
import { findSegment, segmentId } from "../lib/security-segment.js";
import { MAX_EVENT_BYTES, parseNginxErrorLine, parseSecurityAccessLine } from "../lib/security-event-parser.js";
import proxyHostModel from "../models/proxy_host.js";
import settingModel from "../models/setting.js";
import { global as logger } from "../logger.js";

const LOG_DIR = "/data/logs";
const MAX_TOTAL_BYTES = 25 * 1024 * 1024;
const MAX_PER_FILE_BYTES = 5 * 1024 * 1024;
const MAX_LINE_LENGTH = MAX_EVENT_BYTES;
const MAX_EVENTS = 5000;
const MAX_RUNTIME_MS = 5000;
const MAX_GZIP_EXPANSION_RATIO = 25;
const MAX_GZIP_INPUT_BYTES = 64 * 1024 * 1024;
const MAX_GZIP_FINGERPRINT_OUTPUT_BYTES = 64 * 1024 * 1024;
const MAX_DATABASE_ROWS = finitePositive(process.env.SECURITY_EVENT_DATABASE_HIGH_WATER, 1000000);
const MAX_DATABASE_ESTIMATED_BYTES = finitePositive(process.env.SECURITY_EVENT_DATABASE_ESTIMATED_HIGH_WATER_BYTES, 1024 * 1024 * 1024);
const DATABASE_HEADROOM_BYTES = finitePositive(process.env.SECURITY_EVENT_DATABASE_HEADROOM_BYTES, 64 * 1024 * 1024);
const RAW_LOG_DISK_HIGH_WATER_PERCENT = finitePercent(process.env.SECURITY_RAW_LOG_DISK_HIGH_WATER_PERCENT, 90);
const DEFAULT_RETENTION_DAYS = 30;
const MIN_RETENTION_DAYS = 7;
const MAX_RETENTION_DAYS = 365;

function finitePositive(value, fallback) {
	const numeric = Number(value);
	return Number.isFinite(numeric) && numeric > 0 ? Math.floor(numeric) : fallback;
}
function finitePercent(value, fallback) {
	const numeric = Number(value);
	return Number.isFinite(numeric) && numeric > 0 && numeric <= 100 ? numeric : fallback;
}
// Birth time is stable across append and rename, but changes when an inode is
// reused. ctime is deliberately excluded because ordinary appends update it.
const fileKey = (stat) => `${stat.dev}:${stat.ino}:${Math.floor(stat.birthtimeMs || 0)}`;


const retentionDays = async () => {
	const row = await settingModel.query().findById("security-event-retention-days");
	const value = Number.parseInt(row?.value, 10);
	return Number.isInteger(value) && value >= MIN_RETENTION_DAYS && value <= MAX_RETENTION_DAYS ? value : DEFAULT_RETENTION_DAYS;
};

const candidateFiles = (hostId) => {
	const files = [];
	for (let rotation = 30; rotation >= 2; rotation -= 1) files.push({ kind: "security", rotation, path: `${LOG_DIR}/proxy-host-${hostId}_security.log.${rotation}.gz` });
	files.push({ kind: "security", rotation: 1, path: `${LOG_DIR}/proxy-host-${hostId}_security.log.1` });
	files.push({ kind: "security", rotation: 0, path: `${LOG_DIR}/proxy-host-${hostId}_security.log` });
	for (let rotation = 10; rotation >= 2; rotation -= 1) files.push({ kind: "error", rotation, path: `${LOG_DIR}/proxy-host-${hostId}_error.log.${rotation}.gz` });
	files.push({ kind: "error", rotation: 1, path: `${LOG_DIR}/proxy-host-${hostId}_error.log.1.gz` });
	// Also accept an uncompressed .1 left by an older/different rotation policy.
	files.push({ kind: "error", rotation: 1, path: `${LOG_DIR}/proxy-host-${hostId}_error.log.1` });
	files.push({ kind: "error", rotation: 0, path: `${LOG_DIR}/proxy-host-${hostId}_error.log` });
	return files;
};

const getDiskHighWater = () => {
	try {
		const stat = fs.statfsSync(LOG_DIR);
		const total = Number(stat.blocks) * Number(stat.bsize);
		const free = Number(stat.bavail) * Number(stat.bsize);
		return total > 0 && ((total - free) / total) * 100 >= RAW_LOG_DISK_HIGH_WATER_PERCENT;
	} catch { return false; }
};
const eventEstimate = (event) => Buffer.byteLength(JSON.stringify(event), "utf8") + 512;
const safeErrorClass = (err) => {
	if (["gzip-limit", "runtime-limit"].includes(err?.message)) return err.message;
	if (["outside-log-directory", "not-regular-file"].includes(err?.message)) return "unsafe-log-file";
	return "collector-operation-failed";
};

const collector = {
	intervalTimeout: 60 * 1000,
	interval: null,
	running: false,
	initTimer: () => {
		collector.interval = setInterval(collector.fetch, collector.intervalTimeout);
		collector.fetch();
	},
	discoverHosts: async () => proxyHostModel.query().select("id", "domain_names", "owner_user_id", "is_deleted", "enabled"),
	fetch: async () => {
		if (collector.running) return;
		collector.running = true;
		const started = Date.now();
		let bytesRead = 0;
		let linesRead = 0;
		let malformed = 0;
		let pending = 0;
		let limitReached = false;
		let estimatedBytes = 0;
		const events = [];
		const cursors = [];
		try {
			const days = await retentionDays();
			const [countRow, measuredBytes, priorState, hosts] = await Promise.all([
				db()("security_event").count("id as count").first(),
				databaseStorageBytes(db()),
				db()("security_collector_state").first(),
				collector.discoverHosts(),
			]);
			const priorEstimatedBytes = Number(priorState?.estimated_database_bytes || 0);
			const storageBytes = measuredBytes ?? priorEstimatedBytes;
			const databaseHighWater = Number(countRow?.count || 0) >= MAX_DATABASE_ROWS || storageBytes >= MAX_DATABASE_ESTIMATED_BYTES - DATABASE_HEADROOM_BYTES;
			const rawDiskHighWater = getDiskHighWater();
			if (!databaseHighWater && !rawDiskHighWater && process.env.SECURITY_EVENTS_ENABLED !== "false") {
				for (const host of hosts) {
					for (const file of candidateFiles(host.id)) {
						if (Date.now() - started >= MAX_RUNTIME_MS || bytesRead >= MAX_TOTAL_BYTES || events.length >= MAX_EVENTS || estimatedBytes >= DATABASE_HEADROOM_BYTES) {
							limitReached = true; pending += 1; continue;
						}
						let opened;
						try { opened = openSecurityLog(file.path, LOG_DIR); } catch { continue; }
						try {
							const key = fileKey(opened.stat);
							const inspection = await readSecurityLog(opened, {
								compressed: file.path.endsWith(".gz"), byteOffset: 0, maxBytes: 0,
								maxLineLength: MAX_LINE_LENGTH, maxCompressedBytes: MAX_GZIP_INPUT_BYTES, maxOutputBytes: MAX_GZIP_FINGERPRINT_OUTPUT_BYTES,
								maxExpansionRatio: MAX_GZIP_EXPANSION_RATIO, maxRuntimeMs: Math.max(1, MAX_RUNTIME_MS - (Date.now() - started)), fullFingerprint: true,
							});
							if (!inspection.fingerprintComplete) throw new Error("fingerprint-limit");
							const previous = await findSegment(db(), Number(host.id), file.kind, key, inspection.fingerprint, opened.stat.size, file.path, file.path.endsWith(".gz"));
							const cursorOffset = previous ? Number(previous.byte_offset) : 0;
							const increment = await readSecurityLog(opened, {
								compressed: file.path.endsWith(".gz"), byteOffset: cursorOffset, maxBytes: Math.min(MAX_PER_FILE_BYTES, MAX_TOTAL_BYTES - bytesRead),
								maxLineLength: MAX_LINE_LENGTH, maxCompressedBytes: MAX_GZIP_INPUT_BYTES, maxOutputBytes: MAX_PER_FILE_BYTES,
								maxExpansionRatio: MAX_GZIP_EXPANSION_RATIO, maxRuntimeMs: Math.max(1, MAX_RUNTIME_MS - (Date.now() - started)),
							});
							bytesRead += increment.bytes;
							const id = previous?.segment_id || segmentId(host.id, file.kind, key);
							let acceptedOffset = cursorOffset;
							for (const entry of increment.lines) {
								if (events.length >= MAX_EVENTS || estimatedBytes >= DATABASE_HEADROOM_BYTES || Date.now() - started >= MAX_RUNTIME_MS) {
									limitReached = true; pending += 1; break;
								}
								linesRead += 1;
								if (entry.oversized) { malformed += 1; acceptedOffset = entry.endOffset; continue; }
								try {
									const context = { proxyHostId: Number(host.id), segmentId: id, lineOffset: entry.offset };
									const event = file.kind === "security" ? parseSecurityAccessLine(entry.line, context) : parseNginxErrorLine(entry.line, context);
									event.host_domain_snapshot = Array.isArray(host.domain_names) ? host.domain_names[0] || null : null;
									event.owner_user_id_snapshot = host.owner_user_id || null;
									events.push(event);
									estimatedBytes += eventEstimate(event);
								} catch { malformed += 1; }
								acceptedOffset = entry.endOffset;
							}
							if (increment.deferred) pending += 1;
							if (acceptedOffset !== cursorOffset) cursors.push({ segment_id: id, file_key: key, file_path: file.path, log_kind: file.kind, byte_offset: acceptedOffset, content_fingerprint: inspection.fingerprint });
						} catch (err) {
							pending += 1;
							logger.warn(`Security collector deferred ${basename(file.path)}: ${safeErrorClass(err)}`);
						} finally { try { fs.closeSync(opened.fd); } catch { /* closed by stream */ } }
					}
				}
			}
			const state = { last_started_on: new Date(started), last_completed_on: new Date(), last_error_on: null, last_error_summary: null, bytes_read: bytesRead, lines_read: linesRead, malformed_lines: malformed, files_pending: pending, limit_reached: limitReached, database_high_water_reached: databaseHighWater, raw_log_disk_high_water_reached: rawDiskHighWater, estimated_database_bytes: Math.max(storageBytes, priorEstimatedBytes + estimatedBytes) };
			await db().transaction((trx) => writeSecurityEvents(trx, { events, cursors, state, retentionDays: days }));
		} catch (err) {
			logger.error(`Security event collection failed: ${safeErrorClass(err)}`);
			try {
				const values = { last_error_on: new Date(), last_error_summary: safeErrorClass(err) };
				const existing = await db()("security_collector_state").first();
				if (existing) await db()("security_collector_state").where("id", existing.id).update(values);
				else await db()("security_collector_state").insert({ ...values, bytes_read: 0, lines_read: 0, events_inserted: 0, malformed_lines: 0, files_pending: 0, limit_reached: false, database_high_water_reached: false, raw_log_disk_high_water_reached: false });
			} catch { /* preserve API availability */ }
		} finally { collector.running = false; }
	},
	constants: { LOG_DIR, MAX_TOTAL_BYTES, MAX_PER_FILE_BYTES, MAX_LINE_LENGTH, MAX_EVENTS, MAX_RUNTIME_MS, MAX_GZIP_EXPANSION_RATIO, MAX_DATABASE_ROWS, MAX_DATABASE_ESTIMATED_BYTES, DATABASE_HEADROOM_BYTES, RAW_LOG_DISK_HIGH_WATER_PERCENT, DEFAULT_RETENTION_DAYS, MIN_RETENTION_DAYS, MAX_RETENTION_DAYS },
};

export { candidateFiles, retentionDays };
export default collector;
