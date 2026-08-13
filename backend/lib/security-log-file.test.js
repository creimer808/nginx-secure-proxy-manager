import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { SECURITY_LOG_MODE, ensureSecurityLogFile, getSecurityLogPath } from "./security-log-file.js";

let logDir = "";

before(() => {
	logDir = fs.mkdtempSync(path.join(os.tmpdir(), "npm-security-log-"));
});

after(() => {
	fs.rmSync(logDir, { recursive: true, force: true });
});

describe("security log file preparation", () => {
	it("creates a regular 0640 log owned by the backend process", () => {
		const logPath = ensureSecurityLogFile(42, { logDir });
		const stat = fs.lstatSync(logPath);
		assert.equal(stat.isFile(), true);
		assert.equal(stat.isSymbolicLink(), false);
		assert.equal(stat.mode & 0o777, SECURITY_LOG_MODE);
		assert.equal(stat.uid, process.getuid());
		assert.equal(stat.gid, process.getgid());
	});

	it("corrects an existing regular log mode", () => {
		const { logPath } = getSecurityLogPath(43, logDir);
		fs.writeFileSync(logPath, "existing\n", { mode: 0o644 });
		fs.chmodSync(logPath, 0o644);
		ensureSecurityLogFile(43, { logDir });
		assert.equal(fs.statSync(logPath).mode & 0o777, SECURITY_LOG_MODE);
	});

	it("rejects symlinked log files without following them", () => {
		const outsidePath = path.join(logDir, "outside.log");
		const { logPath } = getSecurityLogPath(44, logDir);
		fs.writeFileSync(outsidePath, "outside\n");
		fs.symlinkSync(outsidePath, logPath);
		assert.throws(() => ensureSecurityLogFile(44, { logDir }), /non-symlink/);
		assert.equal(fs.readFileSync(outsidePath, "utf8"), "outside\n");
	});

	it("rejects invalid host identifiers before resolving a path", () => {
		assert.throws(() => ensureSecurityLogFile(0, { logDir }), /Invalid proxy host id/);
		assert.throws(() => ensureSecurityLogFile(Number.NaN, { logDir }), /Invalid proxy host id/);
	});
});
