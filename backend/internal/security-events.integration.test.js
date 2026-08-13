import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import knex from "knex";
import { databaseStorageBytes } from "../lib/security-database-size.js";
import { findSegment } from "../lib/security-segment.js";
import { openSecurityLog, readSecurityLog } from "../lib/security-log-reader.js";
import { up as migrateUp, down as migrateDown } from "../migrations/20260813120000_security_events.js";

const options = { maxBytes: 1024, maxLineLength: 64, maxCompressedBytes: 1024 * 1024, maxOutputBytes: 4096, maxExpansionRatio: 25, maxRuntimeMs: 1000 };
const keyFor = (stat) => `${stat.dev}:${stat.ino}:${Math.floor(stat.birthtimeMs || 0)}`;

const read = async (file, compressed = false, offset = 0, overrides = {}) => {
	const opened = openSecurityLog(file, path.dirname(file));
	try {
		return await readSecurityLog(opened, { ...options, compressed, byteOffset: offset, ...overrides });
	} finally {
		try { fs.closeSync(opened.fd); } catch { /* stream ownership */ }
	}
};

let temp = "";
let database;
const cursor = async ({ host = 1, kind = "security", key, fingerprint, filePath, offset = 0, id }) => {
	await database("security_log_cursor").insert({
		segment_id: id || `security:${host}:${kind}:${crypto.createHash("sha256").update(key).digest("hex")}`,
		file_key: key, content_fingerprint: fingerprint, file_path: filePath, log_kind: kind, byte_offset: offset, updated_on: new Date(),
	});
};

before(async () => {
	temp = fs.mkdtempSync(path.join(os.tmpdir(), "security-events-integration-"));
	database = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
	await migrateUp(database);
});
after(async () => { await migrateDown(database); await database.destroy(); fs.rmSync(temp, { recursive: true, force: true }); });

describe("security collector lifecycle identity", () => {
	it("uses the actual SQLite migration and supports a restart cursor lookup", async () => {
		assert.equal(await database.schema.hasTable("security_event"), true);
		assert.equal(await database.schema.hasTable("security_log_cursor"), true);
		assert.ok((await databaseStorageBytes(database)) > 0);
		const file = path.join(temp, "restart.log");
		fs.writeFileSync(file, "one\\n");
		const first = await read(file);
		const stat = fs.statSync(file);
		await cursor({ key: keyFor(stat), fingerprint: first.fingerprint, filePath: file, offset: first.nextOffset, id: "security:1:security:segment-restart" });
		const restarted = await findSegment(database, 1, "security", keyFor(fs.statSync(file)), first.fingerprint, fs.statSync(file).size, file, false);
		assert.equal(restarted.segment_id, "security:1:security:segment-restart");
	});
	it("keeps an appended short current file in the same generation", async () => {
		const file = path.join(temp, "current.log");
		fs.writeFileSync(file, "one\n");
		const initial = await read(file);
		const stat = fs.statSync(file);
		await cursor({ key: keyFor(stat), fingerprint: initial.fingerprint, filePath: file, offset: initial.nextOffset, id: "security:1:security:segment-append" });
		fs.appendFileSync(file, "two\n");
		const grown = await read(file);
		const matched = await findSegment(database, 1, "security", keyFor(fs.statSync(file)), grown.fingerprint, fs.statSync(file).size, file, false);
		assert.equal(matched.segment_id, "security:1:security:segment-append");
		const increment = await read(file, false, matched.byte_offset);
		assert.deepEqual(increment.lines.map((line) => line.line), ["two"]);
	});

	it("preserves generation across rename and current-to-gzip", async () => {
		const current = path.join(temp, "rotation.log");
		const rotated = `${current}.1`;
		const zipped = `${current}.2.gz`;
		fs.writeFileSync(current, "one\ntwo\n");
		const first = await read(current);
		await cursor({ key: keyFor(fs.statSync(current)), fingerprint: first.fingerprint, filePath: current, offset: first.nextOffset, id: "security:1:security:segment-rotate" });
		fs.renameSync(current, rotated);
		const renamed = await read(rotated);
		const renameMatch = await findSegment(database, 1, "security", keyFor(fs.statSync(rotated)), renamed.fingerprint, fs.statSync(rotated).size, rotated, false);
		assert.equal(renameMatch.segment_id, "security:1:security:segment-rotate");
		fs.writeFileSync(zipped, gzipSync(fs.readFileSync(rotated)));
		const gzip = await read(zipped, true);
		const gzipMatch = await findSegment(database, 1, "security", keyFor(fs.statSync(zipped)), gzip.fingerprint, fs.statSync(zipped).size, zipped, true);
		assert.equal(gzipMatch.segment_id, "security:1:security:segment-rotate");
	});

	it("advances through a gzip backlog beyond one output page with a stable plain-file fingerprint", async () => {
		const plain = path.join(temp, "large-rotation.log");
		const zipped = `${plain}.gz`;
		const content = Array.from({ length: 5000 }, (_, index) => `line-${String(index).padStart(5, "0")}\n`).join("");
		fs.writeFileSync(plain, content);
		fs.writeFileSync(zipped, gzipSync(content));
		const plainRead = await read(plain, false, 0, { maxBytes: 0, fullFingerprint: true });
		const gzipFingerprint = await read(zipped, true, 0, { maxBytes: 0, maxOutputBytes: 1024 * 1024, fullFingerprint: true });
		assert.equal(gzipFingerprint.fingerprint, plainRead.fingerprint);
		let offset = 0;
		let final;
		for (let page = 0; page < 100 && offset < Buffer.byteLength(content); page += 1) {
			final = await read(zipped, true, offset);
			assert.ok(final.nextOffset > offset, `gzip page ${page} did not advance`);
			offset = final.nextOffset;
		}
		assert.equal(offset, Buffer.byteLength(content));
	});

	it("does not conflate equal-length generations that share a 64 KiB prefix", async () => {
		const prefix = "p".repeat(64 * 1024);
		const firstFile = path.join(temp, "prefix-a.log");
		const secondFile = path.join(temp, "prefix-b.log");
		fs.writeFileSync(firstFile, `${prefix}A\n`);
		fs.writeFileSync(secondFile, `${prefix}B\n`);
		const first = await read(firstFile, false, 0, { maxBytes: 0, fullFingerprint: true });
		const second = await read(secondFile, false, 0, { maxBytes: 0, fullFingerprint: true });
		assert.notEqual(first.fingerprint, second.fingerprint);
		await cursor({ key: keyFor(fs.statSync(firstFile)), fingerprint: first.fingerprint, filePath: firstFile, offset: fs.statSync(firstFile).size, id: "security:1:security:segment-prefix" });
		assert.equal(await findSegment(database, 1, "security", keyFor(fs.statSync(secondFile)), second.fingerprint, fs.statSync(secondFile).size, secondFile, false), null);
	});

	it("treats truncation with the same prefix and an inode-reuse key as new generations", async () => {
		const file = path.join(temp, "truncate.log");
		fs.writeFileSync(file, "same-prefix\nold\n");
		const first = await read(file);
		const oldKey = keyFor(fs.statSync(file));
		await cursor({ key: oldKey, fingerprint: first.fingerprint, filePath: file, offset: first.nextOffset, id: "security:1:security:segment-old" });
		fs.writeFileSync(file, "same-prefix\n");
		const replacement = await read(file);
		const truncation = await findSegment(database, 1, "security", oldKey, replacement.fingerprint, fs.statSync(file).size, file, false);
		assert.equal(truncation, null);
		const reused = await findSegment(database, 1, "security", `${oldKey}:different-generation`, replacement.fingerprint, fs.statSync(file).size, file, false);
		assert.equal(reused, null);
	});

	it("defers at byte limits without losing a valid following record and discards an oversized line once", async () => {
		const file = path.join(temp, "limits.log");
		fs.writeFileSync(file, `one\ntwo\n${"x".repeat(100)}\nthree\n`);
		const limited = await (async () => {
			const opened = openSecurityLog(file, temp);
			try { return await readSecurityLog(opened, { ...options, byteOffset: 0, maxBytes: 4, maxLineLength: 64, compressed: false }); }
			finally { try { fs.closeSync(opened.fd); } catch { /* stream ownership */ } }
		})();
		assert.deepEqual(limited.lines.map((line) => line.line), ["one"]);
		assert.equal(limited.deferred, true);
		const second = await read(file, false, limited.nextOffset);
		assert.deepEqual(second.lines.map((line) => line.line), ["two", "", "three"]);
		assert.equal(second.lines.filter((line) => line.oversized).length, 1);
	});
});
