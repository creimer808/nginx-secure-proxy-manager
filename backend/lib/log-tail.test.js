import { strictEqual } from "node:assert";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { readIncremental } from "./log-tail.js";

const tmp = () => fs.mkdtempSync(join(tmpdir(), "npm-log-tail-"));

describe("log-tail readIncremental", () => {
	let dir = "";

	before(() => {
		dir = tmp();
	});

	after(() => {
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it("reads only bytes after the cursor and advances to the final newline", () => {
		const file = join(dir, "a.log");
		fs.writeFileSync(file, "line1\nline2\nline3\n");
		const first = readIncremental({ filePath: file, byteOffset: 0, maxBytes: 4096, maxLineLength: 1024 });
		strictEqual(first.lines.join("|"), "line1|line2|line3");
		strictEqual(first.newByteOffset, 18);
		strictEqual(first.bytesConsumed, 18);

		// Appending two complete lines and one partial line.
		fs.appendFileSync(file, "line4\nline5\npartial");
		const second = readIncremental({ filePath: file, byteOffset: first.newByteOffset, maxBytes: 4096, maxLineLength: 1024 });
		strictEqual(second.lines.join("|"), "line4|line5");
		// Cursor stops at the final newline, before the partial tail.
		strictEqual(second.newByteOffset, first.newByteOffset + "line4\nline5\n".length);
	});

	it("advances by UTF-8 bytes without replaying completed lines", () => {
		const file = join(dir, "utf8.log");
		const firstLine = "request with café and 日本語\n";
		fs.writeFileSync(file, `${firstLine}partial`);

		const first = readIncremental({ filePath: file, byteOffset: 0, maxBytes: 4096, maxLineLength: 1024 });
		strictEqual(first.lines.join("|"), "request with café and 日本語");
		strictEqual(first.newByteOffset, Buffer.byteLength(firstLine));
		strictEqual(first.bytesConsumed, Buffer.byteLength(firstLine));

		fs.appendFileSync(file, " line\n");
		const second = readIncremental({
			filePath: file,
			byteOffset: first.newByteOffset,
			maxBytes: 4096,
			maxLineLength: 1024,
		});
		strictEqual(second.lines.join("|"), "partial line");
	});

	it("rereads a partial line once it is completed", () => {
		const file = join(dir, "b.log");
		fs.writeFileSync(file, "abc");
		const first = readIncremental({ filePath: file, byteOffset: 0, maxBytes: 4096, maxLineLength: 1024 });
		strictEqual(first.lines.length, 0);
		strictEqual(first.newByteOffset, 0);

		fs.appendFileSync(file, "def\n");
		const second = readIncremental({ filePath: file, byteOffset: first.newByteOffset, maxBytes: 4096, maxLineLength: 1024 });
		strictEqual(second.lines.join("|"), "abcdef");
		strictEqual(second.newByteOffset, 7);
	});

	it("resets the cursor when the file is truncated", () => {
		const file = join(dir, "c.log");
		fs.writeFileSync(file, `${"x".repeat(1000)}\n`);
		const first = readIncremental({ filePath: file, byteOffset: 0, maxBytes: 4096, maxLineLength: 2048 });
		strictEqual(first.newByteOffset, 1001);

		// Truncate to a smaller file with fresh content.
		fs.writeFileSync(file, "fresh\n");
		const second = readIncremental({ filePath: file, byteOffset: first.newByteOffset, maxBytes: 4096, maxLineLength: 2048 });
		strictEqual(second.truncated, true);
		// Offset resets to 0 and the fresh content is then read from the start.
		strictEqual(second.newByteOffset, 6);
		strictEqual(second.lines.join("|"), "fresh");
	});

	it("does not stall on an oversized partial line", () => {
		const file = join(dir, "d.log");
		// A partial line longer than the per-line cap, with no newline.
		fs.writeFileSync(file, `${"y".repeat(2048)}`);
		const first = readIncremental({ filePath: file, byteOffset: 0, maxBytes: 4096, maxLineLength: 1024 });
		strictEqual(first.lines.length, 0);
		strictEqual(first.newByteOffset, 2048);
	});

	it("reports a stable device:inode fingerprint for the same file", () => {
		const file = join(dir, "e.log");
		fs.writeFileSync(file, "one\n");
		const a = readIncremental({ filePath: file, byteOffset: 0, maxBytes: 4096, maxLineLength: 1024 });
		const b = readIncremental({ filePath: file, byteOffset: a.newByteOffset, maxBytes: 4096, maxLineLength: 1024 });
		strictEqual(a.fileKey, b.fileKey);
		strictEqual(a.fileKey.includes(":"), true);
	});
});
