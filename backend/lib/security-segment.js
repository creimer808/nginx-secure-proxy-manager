import crypto from "node:crypto";

const segmentPrefix = (hostId, kind) => `security:${hostId}:${kind}:`;
const segmentId = (hostId, kind, key) => `${segmentPrefix(hostId, kind)}${crypto.createHash("sha256").update(key).digest("hex")}`;

/**
 * An inode key keeps a live file stable across appends and renames. A matching
 * decompressed-content fingerprint permits the later gzip representation to
 * inherit that logical generation. A same-path replacement never falls back to
 * content matching, preventing a truncated generation from inheriting a cursor.
 */
const findSegment = async (database, hostId, kind, key, fingerprint, size, filePath, compressed) => {
	const rows = await database("security_log_cursor")
		.where("log_kind", kind)
		.where("segment_id", "like", `${segmentPrefix(hostId, kind)}%`)
		.orderBy("updated_on", "desc");
	const sameInode = rows.find((row) => row.file_key === key && (compressed || Number(row.byte_offset) <= size));
	if (sameInode) return sameInode;
	return rows.find((row) => row.content_fingerprint === fingerprint && row.file_path !== filePath) || null;
};

export { findSegment, segmentId, segmentPrefix };
