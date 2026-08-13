import crypto from "node:crypto";
import fs from "node:fs";
import { basename, sep } from "node:path";
import { Readable } from "node:stream";
import { createGunzip } from "node:zlib";

const READ_CHUNK_BYTES = 64 * 1024;
const FINGERPRINT_BYTES = 64 * 1024;

/** Open once with O_NOFOLLOW and validate the descriptor, not a later pathname. */
const openSecurityLog = (filePath, logDir) => {
	const root = fs.realpathSync(logDir);
	const fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
	try {
		const stat = fs.fstatSync(fd);
		// Compare the pathname's identity with the descriptor to reject swaps
		// between authorization and open without reading the replacement.
		const pathStat = fs.lstatSync(filePath);
		if (!stat.isFile() || stat.nlink !== 1 || pathStat.isSymbolicLink() || pathStat.dev !== stat.dev || pathStat.ino !== stat.ino) {
			throw new Error("unsafe-log-file");
		}
		return { fd, stat, path: `${root}${sep}${basename(filePath)}` };
	} catch (err) {
		fs.closeSync(fd);
		throw err;
	}
};

const createFingerprint = (full = false) => {
	const hash = crypto.createHash("sha256");
	let remaining = full ? Number.MAX_SAFE_INTEGER : FINGERPRINT_BYTES;
	return {
		update: (chunk) => {
			if (remaining <= 0) return;
			const selected = chunk.subarray(0, remaining);
			hash.update(selected);
			remaining -= selected.length;
		},
		complete: () => remaining === 0,
		digest: () => hash.digest("hex"),
	};
};

const createLineCollector = ({ byteOffset, maxBytes, maxLineLength, deadline, startOffset = 0, aborted }) => {
	let logicalOffset = startOffset;
	let recordStart = startOffset;
	let record = Buffer.alloc(0);
	let oversized = false;
	let acceptedBytes = 0;
	let deferred = false;
	const lines = [];
	const stopped = () => Date.now() >= deadline || Boolean(aborted?.());
	const accept = (line, endOffset, isOversized) => {
		if (endOffset <= byteOffset) return true;
		const length = endOffset - recordStart;
		if (acceptedBytes + length > maxBytes || stopped()) {
			deferred = true;
			return false;
		}
		lines.push({ offset: recordStart, endOffset, line: isOversized ? "" : line.toString("utf8"), oversized: isOversized });
		acceptedBytes += length;
		return true;
	};
	const append = (chunk) => {
		let start = 0;
		while (start < chunk.length) {
			if (stopped()) { deferred = true; return false; }
			const newline = chunk.indexOf(0x0a, start);
			const end = newline === -1 ? chunk.length : newline;
			if (!oversized) {
				record = Buffer.concat([record, chunk.subarray(start, end)]);
				if (record.length > maxLineLength) { oversized = true; record = Buffer.alloc(0); }
			}
			logicalOffset += end - start;
			if (newline === -1) break;
			logicalOffset += 1;
			if (!accept(record, logicalOffset, oversized)) return false;
			recordStart = logicalOffset;
			record = Buffer.alloc(0);
			oversized = false;
			start = newline + 1;
		}
		return true;
	};
	return {
		append,
		result: () => ({ lines, nextOffset: lines.length ? lines.at(-1).endOffset : byteOffset, scannedOffset: logicalOffset, bytes: acceptedBytes, deferred: deferred || record.length > 0 || oversized }),
	};
};

const fingerprintDescriptor = (fd, stat, full = false, deadline = Number.MAX_SAFE_INTEGER) => {
	const hash = crypto.createHash("sha256");
	const limit = full ? stat.size : Math.min(stat.size, FINGERPRINT_BYTES);
	let position = 0;
	while (position < limit) {
		if (Date.now() >= deadline) return { digest: hash.digest("hex"), complete: false };
		const buffer = Buffer.alloc(Math.min(READ_CHUNK_BYTES, limit - position));
		const read = fs.readSync(fd, buffer, 0, buffer.length, position);
		if (!read) break;
		hash.update(buffer.subarray(0, read));
		position += read;
	}
	return { digest: hash.digest("hex"), complete: true };
};

const readPlain = ({ fd, stat, byteOffset, maxBytes, maxLineLength, deadline, aborted, fullFingerprint = false }) => {
	let position = byteOffset > stat.size ? 0 : byteOffset;
	const collector = createLineCollector({ byteOffset: position, maxBytes, maxLineLength, deadline, startOffset: position, aborted });
	while (position < stat.size && Date.now() < deadline && !aborted?.()) {
		const buffer = Buffer.alloc(Math.min(READ_CHUNK_BYTES, stat.size - position));
		const read = fs.readSync(fd, buffer, 0, buffer.length, position);
		if (!read || !collector.append(buffer.subarray(0, read))) break;
		position += read;
	}
	const fingerprint = fingerprintDescriptor(fd, stat, fullFingerprint, deadline);
	return { ...collector.result(), fingerprint: fingerprint.digest, fingerprintComplete: fingerprint.complete };
};

const readGzip = async ({ fd, stat, byteOffset, maxBytes, maxLineLength, maxCompressedBytes, maxOutputBytes, maxExpansionRatio, deadline, aborted, fullFingerprint = false }) => {
	let compressedBytes = 0;
	let limited = false;
	// Gzip has no safe random-access offset. Re-decompress from the beginning,
	// but permit enough bounded output to reach the logical cursor plus one page.
	const outputCeiling = Math.min(
		byteOffset + Math.max(maxOutputBytes, maxBytes, FINGERPRINT_BYTES) + maxLineLength,
		Math.max(1, Math.min(stat.size, maxCompressedBytes)) * maxExpansionRatio,
	);
	const source = Readable.from((async function* () {
		let position = 0;
		while (position < stat.size && !limited) {
			if (Date.now() >= deadline || aborted?.()) { limited = true; break; }
			const remaining = Math.min(READ_CHUNK_BYTES, stat.size - position, Math.max(0, maxCompressedBytes - compressedBytes));
			if (!remaining) { limited = true; break; }
			const buffer = Buffer.alloc(remaining);
			const read = fs.readSync(fd, buffer, 0, remaining, position);
			if (!read) break;
			position += read;
			compressedBytes += read;
			yield buffer.subarray(0, read);
			if (compressedBytes >= maxCompressedBytes && position < stat.size) limited = true;
		}
	})());
	const gunzip = createGunzip();
	const collector = createLineCollector({ byteOffset, maxBytes, maxLineLength, deadline, aborted });
	const fingerprint = createFingerprint(fullFingerprint);
	let outputBytes = 0;
	source.pipe(gunzip);
	try {
		for await (const output of gunzip) {
			if (Date.now() >= deadline || aborted?.()) { limited = true; break; }
			const ratioLimit = Math.max(compressedBytes, 1) * maxExpansionRatio;
			const outputLimit = Math.min(outputCeiling, ratioLimit);
			const allowed = Math.min(output.length, Math.max(0, outputLimit - outputBytes));
			if (allowed > 0) {
				const selected = output.subarray(0, allowed);
				outputBytes += selected.length;
				fingerprint.update(selected);
				const accepted = collector.append(selected);
				// Fingerprinting is independent of the page size. Inspection calls use
				// maxBytes=0 and still consume a stable 64 KiB decompressed prefix.
				if (!accepted && !fullFingerprint && fingerprint.complete()) { limited = true; break; }
			}
			if (allowed < output.length || outputBytes >= outputCeiling) { limited = true; break; }
		}
	} catch (err) {
		// A deliberately shortened archive is expected when a safe resource
		// limit stops the scan. Return parsed prefix lines instead of a 500.
		if (!limited) throw err;
	} finally {
		source.destroy();
		gunzip.destroy();
	}
	const result = collector.result();
	return { ...result, deferred: result.deferred || limited, fingerprint: fingerprint.digest(), fingerprintComplete: fullFingerprint ? !limited && compressedBytes === stat.size : fingerprint.complete() };
};

const readSecurityLog = async (opened, options) => {
	const deadline = Date.now() + options.maxRuntimeMs;
	const args = { ...opened, ...options, deadline };
	return options.compressed ? await readGzip(args) : readPlain(args);
};

const splitCompleteLines = (buffer, offset, maxBytes, maxLineLength) => {
	const collector = createLineCollector({ byteOffset: offset, maxBytes, maxLineLength, deadline: Number.MAX_SAFE_INTEGER });
	collector.append(buffer);
	return collector.result();
};

export { openSecurityLog, readSecurityLog, splitCompleteLines };
