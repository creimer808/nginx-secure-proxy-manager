import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { gzipSync } from "node:zlib";
import { openSecurityLog, readSecurityLog, splitCompleteLines } from "../lib/security-log-reader.js";

describe("security collector file reads", () => {
	it("keeps trailing partial lines for the next cycle and bounds input", () => {
		const read = splitCompleteLines(Buffer.from("one\ntwo\npartial"), 0, 1024, 256 * 1024);
		assert.deepEqual(read.lines.map((line) => line.line), ["one", "two"]);
		assert.equal(read.nextOffset, 8);
		assert.equal(read.deferred, true);
	});

	it("marks pathological lines but continues at a newline", () => {
		const read = splitCompleteLines(Buffer.from(`${"x".repeat(300000)}\nok\n`), 0, 400000, 256 * 1024);
		assert.equal(read.lines[0].oversized, true);
		assert.equal(read.lines[1].line, "ok");
	});

	it("reads gzip rotations as complete bounded lines", async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), "security-gzip-"));
		const file = path.join(dir, "security.log.1.gz");
		fs.writeFileSync(file, gzipSync("one\ntwo\n"));
		const opened = openSecurityLog(file, dir);
		try {
			const read = await readSecurityLog(opened, { compressed: true, byteOffset: 0, maxBytes: 4096, maxLineLength: 256 * 1024, maxCompressedBytes: 4096, maxExpansionRatio: 25, maxOutputBytes: 1024 * 1024, maxRuntimeMs: 1000 });
			assert.deepEqual(read.lines.map((line) => line.line), ["one", "two"]);
		} finally {
			try { fs.closeSync(opened.fd); } catch { /* reader may close it */ }
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
