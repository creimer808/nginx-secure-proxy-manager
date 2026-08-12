import fs from "node:fs";

/**
 * Pure-ish incremental file reader used by the traffic collector.
 *
 * Given a file and a byte offset, it returns only the complete newline-terminated
 * lines after the offset and the new offset that points just past the last
 * newline. A trailing partial line is left unread so it can be completed on the
 * next cycle. If the file shrank (truncation) the offset resets to zero.
 *
 * This keeps cursor state testable without a database.
 */

/**
 * @typedef {Object} IncrementalRead
 * @property {string[]}  lines          Complete lines (without trailing newline).
 * @property {number}    newByteOffset  Offset to persist for the next read.
 * @property {boolean}   truncated      True when the file shrank below the offset.
 * @property {string}    fileKey        device:inode fingerprint of the file.
 * @property {number}    size           Current file size in bytes.
 * @property {number}    bytesConsumed  Bytes consumed from the file this read.
 */

/**
 * Read complete lines from a file starting at byteOffset.
 *
 * @param   {{ filePath: string, byteOffset: number, maxBytes: number, maxLineLength: number }}  opts
 * @returns {IncrementalRead}
 */
const readIncremental = ({ filePath, byteOffset, maxBytes, maxLineLength }) => {
	const stat = fs.statSync(filePath);
	const size = stat.size;
	const fileKey = `${stat.dev}:${stat.ino}`;

	let offset = byteOffset;
	let truncated = false;
	if (size < offset) {
		offset = 0;
		truncated = true;
	}

	if (offset >= size) {
		return { lines: [], newByteOffset: offset, truncated, fileKey, size, bytesConsumed: 0 };
	}

	const readLen = Math.min(size - offset, maxBytes);
	const fd = fs.openSync(filePath, "r");
	const buf = Buffer.alloc(readLen);
	fs.readSync(fd, buf, 0, readLen, offset);
	fs.closeSync(fd);

	// Search the raw buffer so the persisted cursor remains a byte offset even
	// when discarded log fields contain multi-byte UTF-8 characters.
	const lastNl = buf.lastIndexOf(0x0a);

	if (lastNl === -1) {
		// No complete line yet. If the partial line exceeds the per-line cap, skip it
		// so a pathological line cannot stall collection forever.
		if (buf.length > maxLineLength) {
			return { lines: [], newByteOffset: offset + readLen, truncated, fileKey, size, bytesConsumed: readLen };
		}
		return { lines: [], newByteOffset: offset, truncated, fileKey, size, bytesConsumed: 0 };
	}

	const consumed = lastNl + 1;
	const lines = buf.subarray(0, consumed).toString("utf8").split("\n");
	if (lines.length > 0 && lines[lines.length - 1] === "") {
		lines.pop();
	}

	return { lines, newByteOffset: offset + consumed, truncated, fileKey, size, bytesConsumed: consumed };
};

export { readIncremental };
