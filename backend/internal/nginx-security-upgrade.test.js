import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, afterEach, before, beforeEach, describe, it } from "node:test";

/**
 * The v0.1.2 startup upgrade rendered every host, swapped them all in, then ran
 * `nginx -t` **and** `nginx -s reload`. Because the backend and Nginx are both
 * s6 longruns with no readiness ordering, the reload usually lost that race, and
 * a failed reload reverted every host to its backup — silently. These tests pin
 * the two properties that fix: a reload is never a commit gate, and one host can
 * never revert another.
 */

let internalNginx;
let root;
let logDirectory;
let tested;
let testFails;

const LEGACY = "server { access_log /data/logs/proxy-host-{id}_access.log proxy; }";
const UPGRADED = "server { access_log /data/logs/proxy-host-{id}_security.log security_json if=$security_log_enabled; }";
const configPath = (id) => path.join(root, `${id}.conf`);
const writeConfig = (id, body) => fs.writeFileSync(configPath(id), body.replaceAll("{id}", String(id)));
const readConfig = (id) => fs.readFileSync(configPath(id), "utf8");
const hosts = (...ids) => ids.map((id) => ({ id }));

before(async () => {
	const configDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "nginx-upgrade-config-"));
	logDirectory = fs.mkdtempSync(path.join(os.tmpdir(), "nginx-upgrade-logs-"));
	process.env.DB_SQLITE_FILE = path.join(configDirectory, "fallback.sqlite");
	process.env.NODE_ENV = "test";
	process.env.NODE_CONFIG_DIR = configDirectory;
	process.env.NSPM_KEYS_FILE = path.join(configDirectory, "keys.json");
	process.env.SECURITY_LOG_DIR = logDirectory;
	internalNginx = (await import("./nginx.js")).default;
});
after(() => fs.rmSync(logDirectory, { recursive: true, force: true }));

beforeEach(() => {
	root = fs.mkdtempSync(path.join(os.tmpdir(), "nginx-upgrade-"));
	tested = 0;
	testFails = () => false;
	internalNginx.getConfigName = (_type, id) => configPath(id);
	internalNginx.renderConfig = async (_type, host) => UPGRADED.replaceAll("{id}", String(host.id));
	internalNginx.test = async () => {
		tested += 1;
		const failing = testFails();
		if (failing) throw new Error(`invalid configuration: ${failing}`);
		return true;
	};
	// A pid file cannot exist in a test environment, which is exactly the
	// startup condition that used to trigger the destructive rollback.
	internalNginx.isRunning = () => false;
});
afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

describe("security logging configuration upgrade", () => {
	it("commits on a passing nginx -t and defers the reload when Nginx is not running", async () => {
		writeConfig(1, LEGACY);
		writeConfig(2, UPGRADED);

		const result = await internalNginx.upgradeProxyHostConfigs(hosts(1, 2));

		assert.equal(result.upgraded, 1);
		assert.equal(result.skipped, 0);
		assert.equal(result.reloadDeferred, true);
		assert.equal(result.lastError, null);
		assert.match(readConfig(1), /_security\.log security_json/);
		assert.equal(fs.existsSync(`${configPath(1)}.security-backup`), false);
		assert.equal(fs.existsSync(`${configPath(1)}.security-upgrade`), false);
		assert.ok(fs.existsSync(path.join(logDirectory, "proxy-host-1_security.log")));
		// One baseline test plus one per upgraded host; the already-upgraded host
		// is skipped before anything is rendered.
		assert.equal(tested, 2);
	});

	it("restores and skips only the host that fails validation", async () => {
		writeConfig(1, LEGACY);
		writeConfig(2, LEGACY);
		writeConfig(3, LEGACY);
		testFails = () => (readConfigSafely(2).includes("security_json") ? "host 2 certificate missing" : false);

		const result = await internalNginx.upgradeProxyHostConfigs(hosts(1, 2, 3));

		assert.equal(result.upgraded, 2);
		assert.equal(result.skipped, 1);
		assert.match(result.lastError, /proxy host 2/);
		assert.match(readConfig(1), /security_json/);
		assert.match(readConfig(3), /security_json/);
		assert.equal(readConfig(2), LEGACY.replaceAll("{id}", "2"));
		assert.equal(fs.existsSync(`${configPath(2)}.security-backup`), false);
		assert.equal(fs.existsSync(`${configPath(2)}.security-upgrade`), false);
	});

	it("recovers a backup left by an interrupted upgrade before deciding", async () => {
		writeConfig(1, UPGRADED);
		fs.writeFileSync(`${configPath(1)}.security-backup`, LEGACY.replaceAll("{id}", "1"));

		const result = await internalNginx.upgradeProxyHostConfigs(hosts(1));

		assert.equal(result.upgraded, 1);
		assert.match(readConfig(1), /security_json/);
		assert.equal(fs.existsSync(`${configPath(1)}.security-backup`), false);
	});

	it("reports rather than guesses when the existing configuration is already invalid", async () => {
		writeConfig(1, LEGACY);
		testFails = () => "unrelated pre-existing error";

		const result = await internalNginx.upgradeProxyHostConfigs(hosts(1));

		assert.equal(result.upgraded, 0);
		assert.equal(result.pending, 1);
		assert.match(result.lastError, /existing Nginx configuration is invalid/);
		assert.equal(readConfig(1), LEGACY.replaceAll("{id}", "1"));
	});

	it("creates a missing config file without needing a backup", async () => {
		const result = await internalNginx.upgradeProxyHostConfigs(hosts(4));

		assert.equal(result.upgraded, 1);
		assert.match(readConfig(4), /security_json/);
		assert.equal(fs.existsSync(`${configPath(4)}.security-backup`), false);
	});
});

function readConfigSafely(id) {
	try {
		return readConfig(id);
	} catch {
		return "";
	}
}
