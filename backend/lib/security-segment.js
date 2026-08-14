import crypto from "node:crypto";

const segmentPrefix = (hostId, kind) => `security:${hostId}:${kind}:`;
const segmentId = (hostId, kind, key) => `${segmentPrefix(hostId, kind)}${crypto.createHash("sha256").update(key).digest("hex")}`;

const segmentRows = (database, hostId, kind) => database("security_log_cursor")
	.where("log_kind", kind)
	.where("segment_id", "like", `${segmentPrefix(hostId, kind)}%`)
	.orderBy("updated_on", "desc");

/**
 * Inode identity alone. This is the cheap path: it needs no file content, so a
 * file whose device/inode/birth time is already known is never re-hashed.
 * A plain file whose recorded offset now exceeds its size was truncated, so it
 * is deliberately not matched and falls through to content identification.
 */
const findSegmentByFileKey = async (database, hostId, kind, key, size, compressed) => {
	const rows = await segmentRows(database, hostId, kind);
	return rows.find((row) => row.file_key === key && (compressed || Number(row.byte_offset) <= size)) || null;
};

/**
 * An inode key keeps a live file stable across appends and renames. A matching
 * decompressed-content fingerprint permits the later gzip representation to
 * inherit that logical generation. A same-path replacement never falls back to
 * content matching, preventing a truncated generation from inheriting a cursor.
 */
const findSegment = async (database, hostId, kind, key, fingerprint, size, filePath, compressed) => {
	const rows = await segmentRows(database, hostId, kind);
	const sameInode = rows.find((row) => row.file_key === key && (compressed || Number(row.byte_offset) <= size));
	if (sameInode) return sameInode;
	return rows.find((row) => row.content_fingerprint === fingerprint && row.file_path !== filePath) || null;
};

export { findSegment, findSegmentByFileKey, segmentId, segmentPrefix };
