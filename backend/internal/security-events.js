import fs from "node:fs";
import { basename } from "node:path";
import db from "../db.js";
import { databaseStorageBytes } from "../lib/security-database-size.js";
import { writeSecurityEvents } from "../lib/security-event-commit.js";
import { openSecurityLog, readSecurityLog } from "../lib/security-log-reader.js";
import { findSegment, findSegmentByFileKey, segmentId } from "../lib/security-segment.js";
import { MAX_EVENT_BYTES, parseNginxErrorLine, parseSecurityAccessLine } from "../lib/security-event-parser.js";
import proxyHostModel from "../models/proxy_host.js";
import { global as logger } from "../logger.js";

const DEFAULT_LOG_DIR = "/data/logs";
const MAX_TOTAL_BYTES = 25 * 1024 * 1024;
const MAX_PER_FILE_BYTES = 5 * 1024 * 1024;
const MAX_LINE_LENGTH = MAX_EVENT_BYTES;
const MAX_EVENTS = 5000;
const MAX_RUNTIME_MS = 5000;
// Identifying a file is bookkeeping, not ingestion, so it gets its own budget
// and its cost is excluded from MAX_RUNTIME_MS. Without this an expensive
// fingerprint can consume the whole cycle before a single line is read.
const MAX_FINGERPRINT_RUNTIME_MS = 2000;
const MAX_FINGERPRINT_BYTES = 32 * 1024 * 1024;
// Whatever else happens, one file per cycle is always allowed to finish, so a
// cycle can never end having advanced no cursor at all.
const GUARANTEED_FILE_RUNTIME_MS = 5000;
// Log data the system generated itself is highly repetitive; a ratio tuned for
// untrusted uploads rejects ordinary Nginx archives.
const MAX_GZIP_EXPANSION_RATIO = 500;
const MAX_GZIP_INPUT_BYTES = 64 * 1024 * 1024;
const MAX_GZIP_FINGERPRINT_OUTPUT_BYTES = 64 * 1024 * 1024;
const MAX_DATABASE_ROWS = finitePositive(process.env.SECURITY_EVENT_DATABASE_HIGH_WATER, 1000000);
const MAX_DATABASE_ESTIMATED_BYTES = finitePositive(process.env.SECURITY_EVENT_DATABASE_ESTIMATED_HIGH_WATER_BYTES, 1024 * 1024 * 1024);
const DATABASE_HEADROOM_BYTES = finitePositive(process.env.SECURITY_EVENT_DATABASE_HEADROOM_BYTES, 64 * 1024 * 1024);
const RAW_LOG_DISK_HIGH_WATER_PERCENT = finitePercent(process.env.SECURITY_RAW_LOG_DISK_HIGH_WATER_PERCENT, 90);
const DEFAULT_RETENTION_DAYS = 30;
const MIN_RETENTION_DAYS = 7;
const MAX_RETENTION_DAYS = 365;
// Requests that never reached a proxy host — unknown Host headers, raw-IP hits,
// background scanning. Stored with a null proxy host, so the existing
// visibility guard keeps them administrator-only.
const FALLBACK_HOST_ID = 0;

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

/**
 * The log directory and database are seams rather than constants so a whole
 * collection cycle can be exercised outside a container. Root cause B of the
 * v0.1.3 remediation was unreachable from tests precisely because it was not.
 */
let logDirectory = process.env.SECURITY_LOG_DIR || DEFAULT_LOG_DIR;
let databaseFactory = db;

const retentionDays = async () => {
	const row = await databaseFactory()("setting").where("id", "security-event-retention-days").first();
	const value = Number.parseInt(row?.value, 10);
	return Number.isInteger(value) && value >= MIN_RETENTION_DAYS && value <= MAX_RETENTION_DAYS ? value : DEFAULT_RETENTION_DAYS;
};

/**
 * Newest first. The current file always precedes its own archives, so live
 * telemetry is never starved by weeks-old rotations when a budget runs out.
 */
const candidateFiles = (hostId) => {
	const files = [];
	const prefix = Number(hostId) === FALLBACK_HOST_ID ? "fallback" : `proxy-host-${hostId}`;
	const push = (kind, rotation, name) => files.push({ kind, rotation, path: `${logDirectory}/${name}` });
	push("security", 0, `${prefix}_security.log`);
	push("security", 1, `${prefix}_security.log.1`);
	for (let rotation = 2; rotation <= 30; rotation += 1) push("security", rotation, `${prefix}_security.log.${rotation}.gz`);
	// The fallback server writes no per-host error log; its errors land in the
	// shared fallback_http_error.log, which is browsable but not attributable.
	if (Number(hostId) === FALLBACK_HOST_ID) return files;
	push("error", 0, `${prefix}_error.log`);
	push("error", 1, `${prefix}_error.log.1`);
	// Also accept a compressed .1 left by an older/different rotation policy.
	push("error", 1, `${prefix}_error.log.1.gz`);
	for (let rotation = 2; rotation <= 10; rotation += 1) push("error", rotation, `${prefix}_error.log.${rotation}.gz`);
	return files;
};

const getDiskHighWater = () => {
	try {
		const stat = fs.statfsSync(logDirectory);
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
	discoverHosts: async () => {
		const hosts = await proxyHostModel.query().select("id", "domain_names", "owner_user_id").where("is_deleted", 0).andWhere("enabled", 1);
		return [{ id: FALLBACK_HOST_ID, domain_names: null, owner_user_id: null }, ...hosts];
	},
	fetch: async () => {
		if (collector.running) return;
		collector.running = true;
		const started = Date.now();
		let bytesRead = 0;
		let linesRead = 0;
		let acceptedLines = 0;
		let malformed = 0;
		let pending = 0;
		let limitReached = false;
		let estimatedBytes = 0;
		let fingerprintMs = 0;
		let fingerprintBytes = 0;
		let guaranteeUsed = false;
		let resume = null;
		const events = [];
		const cursors = [];
		// Fingerprint cost is deliberately excluded: identification must never
		// spend the budget that reads new telemetry.
		const elapsed = () => Date.now() - started - fingerprintMs;
		const budgetExhausted = () => elapsed() >= MAX_RUNTIME_MS || bytesRead >= MAX_TOTAL_BYTES || events.length >= MAX_EVENTS || estimatedBytes >= DATABASE_HEADROOM_BYTES;
		/**
		 * Fingerprint a file within the identification budget. Returns null when
		 * the budget is already spent, so the caller can defer rather than stall.
		 */
		const identify = async (opened, file) => {
			const remainingMs = MAX_FINGERPRINT_RUNTIME_MS - fingerprintMs;
			const remainingBytes = MAX_FINGERPRINT_BYTES - fingerprintBytes;
			if (remainingMs <= 0 || remainingBytes <= 0) return null;
			const fullBudget = fingerprintMs === 0 && fingerprintBytes === 0;
			const at = Date.now();
			try {
				const inspection = await readSecurityLog(opened, {
					compressed: file.path.endsWith(".gz"), byteOffset: 0, maxBytes: 0,
					maxLineLength: MAX_LINE_LENGTH, maxCompressedBytes: MAX_GZIP_INPUT_BYTES,
					maxOutputBytes: Math.min(MAX_GZIP_FINGERPRINT_OUTPUT_BYTES, remainingBytes),
					maxFingerprintBytes: remainingBytes, maxExpansionRatio: MAX_GZIP_EXPANSION_RATIO,
					maxRuntimeMs: remainingMs, fullFingerprint: true,
				});
				fingerprintBytes += Number(inspection.fingerprintBytes || 0);
				return { ...inspection, fullBudget };
			} finally { fingerprintMs += Date.now() - at; }
		};
		try {
			const days = await retentionDays();
			const [countRow, measuredBytes, priorState, hosts] = await Promise.all([
				databaseFactory()("security_event").count("id as count").first(),
				databaseStorageBytes(databaseFactory()),
				databaseFactory()("security_collector_state").first(),
				collector.discoverHosts(),
			]);
			const priorEstimatedBytes = Number(priorState?.estimated_database_bytes || 0);
			const storageBytes = measuredBytes ?? priorEstimatedBytes;
			const databaseHighWater = Number(countRow?.count || 0) >= MAX_DATABASE_ROWS || storageBytes >= MAX_DATABASE_ESTIMATED_BYTES - DATABASE_HEADROOM_BYTES;
			const rawDiskHighWater = getDiskHighWater();
			// One flat sweep list makes the resume pointer a single index and lets
			// the cycle continue round-robin instead of restarting at host[0].
			const targets = [];
			for (const host of hosts) {
				let index = 0;
				for (const file of candidateFiles(Number(host.id))) targets.push({ host, file, index: index++ });
			}
			const previousStop = targets.findIndex((target) => Number(target.host.id) === Number(priorState?.last_host_id) && target.index === Number(priorState?.last_candidate_index));
			const startAt = previousStop >= 0 ? previousStop + 1 : 0;

			if (!databaseHighWater && !rawDiskHighWater && process.env.SECURITY_EVENTS_ENABLED !== "false") {
				for (let step = 0; step < targets.length; step += 1) {
					const { host, file, index } = targets[(startAt + step) % targets.length];
					const hostId = Number(host.id);
					const compressed = file.path.endsWith(".gz");
					let opened;
					// A path that does not exist is not pending work. Roughly nine in ten
					// candidate slots are rotations that have never been created.
					try { opened = openSecurityLog(file.path, logDirectory); } catch { continue; }
					try {
						// The progress guarantee: if the budget is gone and nothing at all
						// has been read this cycle, let exactly one file run to completion.
						const exhausted = budgetExhausted();
						const guaranteed = exhausted && acceptedLines === 0 && !guaranteeUsed;
						if (exhausted && !guaranteed) { limitReached = true; pending += 1; continue; }
						if (guaranteed) guaranteeUsed = true;

						const key = fileKey(opened.stat);
						let previous = await findSegmentByFileKey(databaseFactory(), hostId, file.kind, key, opened.stat.size, compressed);
						let fingerprint = previous?.content_fingerprint || null;
						let fingerprintSize = previous ? Number(previous.fingerprint_size || 0) : 0;
						if (previous && fingerprintSize !== opened.stat.size) {
							// The stored fingerprint is what a later gzip representation matches
							// against, so refresh it once the file changes — but only while the
							// identification budget allows. An unchanged file is never re-hashed.
							const refreshed = await identify(opened, file);
							if (refreshed?.fingerprintComplete) { fingerprint = refreshed.fingerprint; fingerprintSize = opened.stat.size; }
						} else if (!previous) {
							const inspection = await identify(opened, file);
							if (inspection?.fingerprintComplete) {
								fingerprint = inspection.fingerprint;
								fingerprintSize = opened.stat.size;
								previous = await findSegment(databaseFactory(), hostId, file.kind, key, fingerprint, opened.stat.size, file.path, compressed);
							} else if (inspection?.fullBudget) {
								// A whole fresh budget was not enough: this file will never be
								// fully hashed, so treat it as a new generation rather than
								// discarding it on every cycle for the rest of time.
								fingerprint = inspection.fingerprint;
								fingerprintSize = 0;
								logger.warn(`Security collector could not fully identify ${basename(file.path)}; starting a new segment`);
							} else {
								// Only the meter stopped us. A fresh budget next cycle will finish.
								pending += 1;
								continue;
							}
						}

						const cursorOffset = previous ? Number(previous.byte_offset) : 0;
						const increment = await readSecurityLog(opened, {
							compressed, byteOffset: cursorOffset, maxBytes: Math.min(MAX_PER_FILE_BYTES, Math.max(0, MAX_TOTAL_BYTES - bytesRead)),
							maxLineLength: MAX_LINE_LENGTH, maxCompressedBytes: MAX_GZIP_INPUT_BYTES, maxOutputBytes: MAX_PER_FILE_BYTES,
							maxExpansionRatio: MAX_GZIP_EXPANSION_RATIO,
							maxRuntimeMs: guaranteed ? GUARANTEED_FILE_RUNTIME_MS : Math.max(1, MAX_RUNTIME_MS - elapsed()),
						});
						bytesRead += increment.bytes;
						const id = previous?.segment_id || segmentId(hostId, file.kind, key);
						let acceptedOffset = cursorOffset;
						// Every line already read is parsed. Stopping part way through an
						// in-memory batch buys nothing and is how a cursor gets stranded.
						for (const entry of increment.lines) {
							if (events.length >= MAX_EVENTS || estimatedBytes >= DATABASE_HEADROOM_BYTES) {
								limitReached = true; pending += 1; break;
							}
							linesRead += 1;
							acceptedLines += 1;
							if (entry.oversized) { malformed += 1; acceptedOffset = entry.endOffset; continue; }
							try {
								const context = { proxyHostId: hostId === FALLBACK_HOST_ID ? null : hostId, segmentId: id, lineOffset: entry.offset };
								const event = file.kind === "security" ? parseSecurityAccessLine(entry.line, context) : parseNginxErrorLine(entry.line, context);
								event.host_domain_snapshot = Array.isArray(host.domain_names) ? host.domain_names[0] || null : null;
								event.owner_user_id_snapshot = host.owner_user_id || null;
								events.push(event);
								estimatedBytes += eventEstimate(event);
							} catch { malformed += 1; }
							acceptedOffset = entry.endOffset;
						}
						if (increment.deferred) pending += 1;
						if (acceptedOffset !== cursorOffset || !previous || fingerprint !== previous.content_fingerprint) {
							cursors.push({ segment_id: id, file_key: key, file_path: file.path, log_kind: file.kind, byte_offset: acceptedOffset, content_fingerprint: fingerprint || "", fingerprint_size: fingerprintSize });
						}
						resume = { hostId, index };
					} catch (err) {
						pending += 1;
						logger.warn(`Security collector deferred ${basename(file.path)}: ${safeErrorClass(err)}`);
					} finally { try { fs.closeSync(opened.fd); } catch { /* closed by stream */ } }
				}
			}
			const state = {
				last_started_on: new Date(started), last_completed_on: new Date(), last_error_on: null, last_error_summary: null,
				bytes_read: bytesRead, lines_read: linesRead, malformed_lines: malformed, files_pending: pending, limit_reached: limitReached,
				database_high_water_reached: databaseHighWater, raw_log_disk_high_water_reached: rawDiskHighWater,
				estimated_database_bytes: Math.max(storageBytes, priorEstimatedBytes + estimatedBytes),
				last_host_id: resume ? resume.hostId : null, last_candidate_index: resume ? resume.index : null,
			};
			await databaseFactory().transaction((trx) => writeSecurityEvents(trx, { events, cursors, state, retentionDays: days }));
		} catch (err) {
			logger.error(`Security event collection failed: ${safeErrorClass(err)}`);
			try {
				const values = { last_error_on: new Date(), last_error_summary: safeErrorClass(err) };
				const existing = await databaseFactory()("security_collector_state").first();
				if (existing) await databaseFactory()("security_collector_state").where("id", existing.id).update(values);
				else await databaseFactory()("security_collector_state").insert({ ...values, bytes_read: 0, lines_read: 0, events_inserted: 0, malformed_lines: 0, files_pending: 0, limit_reached: false, database_high_water_reached: false, raw_log_disk_high_water_reached: false });
			} catch { /* preserve API availability */ }
		} finally { collector.running = false; }
	},
	constants: { LOG_DIR: DEFAULT_LOG_DIR, FALLBACK_HOST_ID, MAX_TOTAL_BYTES, MAX_PER_FILE_BYTES, MAX_LINE_LENGTH, MAX_EVENTS, MAX_RUNTIME_MS, MAX_FINGERPRINT_RUNTIME_MS, MAX_FINGERPRINT_BYTES, GUARANTEED_FILE_RUNTIME_MS, MAX_GZIP_EXPANSION_RATIO, MAX_DATABASE_ROWS, MAX_DATABASE_ESTIMATED_BYTES, DATABASE_HEADROOM_BYTES, RAW_LOG_DISK_HIGH_WATER_PERCENT, DEFAULT_RETENTION_DAYS, MIN_RETENTION_DAYS, MAX_RETENTION_DAYS },
};

/** Test-only seams keep a full collection cycle runnable outside a container. */
const configureSecurityCollectorForTesting = ({ database, logDirectory: nextLogDirectory } = {}) => {
	if (database) databaseFactory = () => database;
	if (nextLogDirectory) logDirectory = nextLogDirectory;
};
const resetSecurityCollectorTestState = () => {
	databaseFactory = db;
	logDirectory = process.env.SECURITY_LOG_DIR || DEFAULT_LOG_DIR;
	collector.running = false;
};

export { candidateFiles, configureSecurityCollectorForTesting, FALLBACK_HOST_ID, resetSecurityCollectorTestState, retentionDays };
export default collector;
