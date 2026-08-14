import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(dirname, "../..");
const image = process.env.SECURITY_NGINX_TEST_IMAGE;
const runtimeEnabled = Boolean(image);
let tmp = "";
let containerName = "";
let ports = {};

const docker = (args, options = {}) => execFileSync("docker", args, { encoding: "utf8", ...options });

const writeFixture = () => {
	const dataRoot = path.join(tmp, "data");
	for (const directory of [
		"data/nginx/custom", "data/nginx/default_host", "data/nginx/proxy_host", "data/nginx/redirection_host", "data/nginx/dead_host", "data/nginx/temp",
		"data/logs", "run/nginx", "tmp/nginx/body", "var/lib/nginx/cache/public", "var/lib/nginx/cache/private", "var/cache/nginx/proxy_temp",
	]) {
		fs.mkdirSync(path.join(tmp, directory), { recursive: true, mode: 0o777 });
		fs.chmodSync(path.join(tmp, directory), 0o777);
	}

	fs.writeFileSync(path.join(dataRoot, "logs/fallback_error.log"), "");
	fs.writeFileSync(path.join(dataRoot, "nginx/proxy_host/security-fixture.conf"), `
server {
  listen 8080;
  set $security_proxy_host_id 12;
  set $security_exploit_protection_enabled 1;
  access_log /data/logs/proxy-host-12_access.log proxy;
  access_log /data/logs/proxy-host-12_security.log security_json if=$security_log_enabled;
  error_log /data/logs/proxy-host-12_error.log warn;
  include conf.d/include/block-exploits.conf;
  location = /status401 { return 401; }
  location = /status403 { return 403; }
  location = /status404 { return 404; }
  location = /status429 { return 429; }
  location = /status500 { return 500; }
  location / { return 200 "ok\\n"; }
}
# This mirrors a legacy generated/default config: the include itself must retain
# exploit blocking even when no new per-host variable was rendered yet.
server {
  listen 8081;
  access_log /data/logs/proxy-host-legacy_access.log proxy;
  access_log /data/logs/proxy-host-legacy_security.log security_json if=$security_log_enabled;
  error_log /data/logs/proxy-host-legacy_error.log warn;
  include conf.d/include/block-exploits.conf;
  location / { return 200 "ok\\n"; }
}
# This mirrors the default/fallback server: no proxy host owns the request, so
# the record carries an empty id and stays administrator-only.
server {
  listen 8083;
  access_log /data/logs/fallback_security.log security_json if=$security_log_enabled;
  error_log /data/logs/fallback_http_error.log warn;
  include conf.d/include/block-exploits.conf;
  location = /status404 { return 404; }
  location / { return 200 "ok\\n"; }
}
server {
  listen 8082;
  set $security_proxy_host_id 13;
  set $security_exploit_protection_enabled 0;
  access_log /data/logs/proxy-host-13_access.log proxy;
  access_log /data/logs/proxy-host-13_security.log security_json if=$security_log_enabled;
  error_log /data/logs/proxy-host-13_error.log warn;
  location / { return 200 "ok\\n"; }
}
`);
	fs.chmodSync(tmp, 0o777);
};

const hostPort = (containerPort) => {
	const mapping = docker(["port", containerName, `${containerPort}/tcp`]).trim();
	const hostPortValue = mapping.match(/:(\d+)$/)?.[1];
	if (!hostPortValue) {
		const logs = docker(["logs", containerName]);
		throw new Error(`Container did not publish ${containerPort}/tcp: ${logs}`);
	}
	return hostPortValue;
};

const requestStatus = (port, requestTarget, options = {}) => {
	const args = ["--path-as-is", "-sS", "-o", os.devNull, "-w", "%{http_code}"];
	if (options.userAgent) {
		args.push("-A", options.userAgent);
	}
	if (options.referrer) {
		args.push("-e", options.referrer);
	}
	args.push(`http://127.0.0.1:${port}${requestTarget}`);
	const result = spawnSync("curl", args, { encoding: "utf8" });
	assert.equal(result.status, 0, result.stderr);
	return result.stdout;
};

const securityEvents = (name) => {
	const file = path.join(tmp, "data/logs", name);
	const raw = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
	return raw.trim() ? raw.trim().split("\n").map(JSON.parse) : [];
};

const legacyFixtures = [
	["sql.union-select", "/?union=select("],
	["sql.union-all-select", "/?union=allselect"],
	["sql.concat", "/?concat=("],
	["file.remote-url-parameter", "/?x=http://"],
	["file.path-traversal", "/?x=../"],
	["file.absolute-path", "/?x=/a/b//"],
	["common.script-tag", "/?x=<script>"],
	["php.globals", "/?GLOBALS="],
	["php.request", "/?_REQUEST="],
	["lfi.proc-self-environ", "/?x=proc/self/environ"],
	["joomla.mosconfig", "/?mosConfig_test=%3D"],
	["php.base64-code", "/?x=base64_encode()"],
	["spam.keyword-group-1", "/?x=viagra"],
	["spam.keyword-group-2", "/?x=levitra"],
	["spam.keyword-group-3", "/?x=cialis"],
	["spam.keyword-group-4", "/?x=tramadol"],
	["ua.indy-library", "/", { userAgent: "Indy Library" }],
	["ua.libwww-perl", "/", { userAgent: "libwww-perl" }],
	["ua.getright", "/", { userAgent: "GetRight" }],
	["ua.getweb", "/", { userAgent: "GetWeb!" }],
	["ua.gozilla", "/", { userAgent: "Go!Zilla" }],
	["ua.download-demon", "/", { userAgent: "Download Demon" }],
	["ua.go-ahead-got-it", "/", { userAgent: "Go-Ahead-Got-It" }],
	["ua.turnitinbot", "/", { userAgent: "TurnitinBot" }],
	["ua.grabnet", "/", { userAgent: "GrabNet" }],
];

describe("security attribution Nginx runtime", { skip: !runtimeEnabled && "Set SECURITY_NGINX_TEST_IMAGE to run against a candidate image" }, () => {
	before(() => {
		// Keep bind mounts below the checkout, which is shared with Docker Desktop
		// in development and CI; /tmp is not always mountable by the daemon.
		tmp = fs.mkdtempSync(path.join(projectRoot, "nginx-security-test-"));
		containerName = `npm-security-${process.pid}-${Date.now()}`;
		writeFixture();
		const mount = (source, target) => ["-v", `${source}:${target}:ro`];
		const args = [
			"run", "-d", "--name", containerName,
			"-p", "127.0.0.1::8080", "-p", "127.0.0.1::8081", "-p", "127.0.0.1::8082", "-p", "127.0.0.1::8083",
			...mount(path.join(projectRoot, "docker/rootfs/etc/nginx/nginx.conf"), "/etc/nginx/nginx.conf"),
			...mount(path.join(projectRoot, "docker/rootfs/etc/nginx/conf.d/include/log-proxy.conf"), "/etc/nginx/conf.d/include/log-proxy.conf"),
			...mount(path.join(projectRoot, "docker/rootfs/etc/nginx/conf.d/include/security-rules.conf"), "/etc/nginx/conf.d/include/security-rules.conf"),
			...mount(path.join(projectRoot, "docker/rootfs/etc/nginx/conf.d/include/block-exploits.conf"), "/etc/nginx/conf.d/include/block-exploits.conf"),
			"-v", `${path.join(tmp, "data")}:/data`, "-v", `${path.join(tmp, "run/nginx")}:/run/nginx`,
			"-v", `${path.join(tmp, "tmp/nginx")}:/tmp/nginx`, "-v", `${path.join(tmp, "var/lib/nginx/cache")}:/var/lib/nginx/cache`,
			"-v", `${path.join(tmp, "var/cache/nginx")}:/var/cache/nginx`, "--entrypoint", "sh", image,
			"-c", "printf 'npm:x:1000:1000::/nonexistent:/usr/sbin/nologin\\n' >> /etc/passwd; printf 'npm:x:1000:\\n' >> /etc/group; nginx", 
		];
		docker(args);
		ports = { enabled: hostPort(8080), legacy: hostPort(8081), disabled: hostPort(8082), fallback: hostPort(8083) };
		let running = false;
		for (let attempt = 0; attempt < 20; attempt += 1) {
			if (spawnSync("curl", ["-sS", `http://127.0.0.1:${ports.enabled}/`], { encoding: "utf8" }).status === 0) {
				running = true;
				break;
			}
			Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);
		}
		assert.equal(running, true, "fixture Nginx did not start");
	});

	after(() => {
		spawnSync("docker", ["rm", "-f", containerName]);
		fs.rmSync(tmp, { recursive: true, force: true });
	});

	it("preserves every legacy rule and records its stable first-match ID", () => {
		for (const [ruleId, requestTarget, options] of legacyFixtures) {
			assert.equal(requestStatus(ports.enabled, requestTarget, options), "403", ruleId);
		}
		const events = securityEvents("proxy-host-12_security.log");
		assert.deepEqual(events.map((event) => event.rule_id), legacyFixtures.map(([ruleId]) => ruleId));
		for (const event of events) {
			assert.equal(event.event_type, "exploit_rule");
			assert.equal(event.severity, "high");
			assert.equal(event.rule_action, "block");
			assert.equal(event.status, "403");
		}
	});

	it("uses the first query rule before later query or user-agent matches", () => {
		assert.equal(requestStatus(ports.enabled, "/?union=allselect(", { userAgent: "GetRight" }), "403");
		const event = securityEvents("proxy-host-12_security.log").at(-1);
		assert.equal(event.rule_id, "sql.union-select");
	});

	it("records only selected status observations and escapes hostile metadata as JSON", () => {
		for (const [target, status, severity] of [
			["/status401", "401", "low"], ["/status403", "403", "medium"], ["/status404", "404", "low"],
			["/status429", "429", "medium"], ["/status500", "500", "medium"],
		]) {
			assert.equal(requestStatus(ports.enabled, target), status);
			const event = securityEvents("proxy-host-12_security.log").at(-1);
			assert.equal(event.event_type, "http_status");
			assert.equal(event.severity, severity);
			assert.equal(event.rule_id, "");
		}
		const before = securityEvents("proxy-host-12_security.log").length;
		assert.equal(requestStatus(ports.enabled, "/?union=select(&note=%22%5C%E2%98%83", {
			userAgent: 'quote " slash \\ snowman ☃', referrer: "https://example.test/a?token=%22%5C☃",
		}), "403");
		const afterAttack = securityEvents("proxy-host-12_security.log");
		const event = afterAttack.at(-1);
		assert.equal(event.http_user_agent, 'quote " slash \\ snowman ☃');
		assert.equal(event.http_referer, "https://example.test/a?token=%22%5C☃");
		assert.ok(afterAttack.length >= before + 1);
		assert.equal(requestStatus(ports.enabled, "/benign"), "200");
		assert.equal(securityEvents("proxy-host-12_security.log").length, afterAttack.length);
	});

	it("keeps legacy includes active and disabled hosts unblocked", () => {
		assert.equal(requestStatus(ports.legacy, "/?union=select("), "403");
		assert.equal(requestStatus(ports.disabled, "/?union=select("), "200");
		assert.equal(securityEvents("proxy-host-13_security.log").length, 0);
	});

	it("records unattributed traffic that never reaches a proxy host", () => {
		assert.equal(requestStatus(ports.fallback, "/?union=select("), "403");
		assert.equal(requestStatus(ports.fallback, "/status404"), "404");
		assert.equal(requestStatus(ports.fallback, "/benign"), "200");
		const events = securityEvents("fallback_security.log");
		assert.equal(events.length, 2, "a 200 must not be recorded");
		assert.equal(events[0].proxy_host_id, "");
		assert.equal(events[0].rule_id, "sql.union-select");
		assert.equal(events[0].event_type, "exploit_rule");
		assert.equal(events[1].event_type, "http_status");
	});
});
