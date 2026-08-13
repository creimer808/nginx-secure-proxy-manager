import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";

const dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(dirname, "../..");
const read = (file) => fs.readFileSync(path.join(projectRoot, file), "utf8");
const rules = read("docker/rootfs/etc/nginx/conf.d/include/security-rules.conf");
const block = read("docker/rootfs/etc/nginx/conf.d/include/block-exploits.conf");
const logFormat = read("docker/rootfs/etc/nginx/conf.d/include/log-proxy.conf");
const defaultConfig = read("docker/rootfs/etc/nginx/conf.d/default.conf");
const template = read("backend/templates/proxy_host.conf");
const logrotate = read("docker/rootfs/etc/logrotate.d/nginx-proxy-manager");
const setup = read("backend/setup.js");

const expectedRules = [
	"sql.union-select", "sql.union-all-select", "sql.concat", "file.remote-url-parameter", "file.path-traversal",
	"file.absolute-path", "common.script-tag", "php.globals", "php.request", "lfi.proc-self-environ",
	"joomla.mosconfig", "php.base64-code", "spam.keyword-group-1", "spam.keyword-group-2", "spam.keyword-group-3",
	"spam.keyword-group-4", "ua.indy-library", "ua.libwww-perl", "ua.getright", "ua.getweb", "ua.gozilla",
	"ua.download-demon", "ua.go-ahead-got-it", "ua.turnitinbot", "ua.grabnet",
];

const securityLogrotateBlock = logrotate.match(/\/data\/logs\/proxy-host-\*_security\.log \{[\s\S]*?\n\}/)?.[0] || "";

describe("security attribution Nginx contract", () => {
	it("keeps every legacy signature mapped to one stable rule ID", () => {
		for (const id of expectedRules) {
			assert.match(rules, new RegExp(`${id.replace(".", "\\.")};`));
		}
		assert.equal((rules.match(/\b(?:sql|file|common|php|lfi|joomla|spam|ua)\.[a-z0-9-]+;/g) || []).length, expectedRules.length);
	});

	it("preserves first-match priority for overlapping query and user-agent rules", () => {
		const sqlFirst = rules.indexOf("sql.union-select;");
		const sqlSecond = rules.indexOf("sql.union-all-select;");
		const queryMap = rules.indexOf("map $query_string $security_query_rule_id");
		const userAgentMap = rules.indexOf("map $http_user_agent $security_user_agent_rule_id");
		assert.ok(queryMap < sqlFirst && sqlFirst < sqlSecond);
		assert.ok(queryMap < userAgentMap);
		assert.match(rules, /map \$security_query_rule_id \$security_detected_rule_id \{\s*""\s+\$security_user_agent_rule_id;\s*default \$security_query_rule_id;/);
	});

	it("keeps legacy and default-server blocking enabled through the include", () => {
		assert.match(block, /set \$security_exploit_protection_enabled 1;/);
		assert.match(block, /if \(\$security_rule_id != ""\) \{\s*return 403;/);
		assert.match(defaultConfig, /include conf\.d\/include\/block-exploits\.conf;/);
		assert.match(template, /set \$security_exploit_protection_enabled/);
	});

	it("labels matches and status observations without logging benign 2xx responses", () => {
		assert.match(rules, /~\^\.\+:\s+exploit_rule;/);
		for (const status of ["401", "403", "404", "429"]) {
			assert.ok(rules.includes(`~^:${status}$       http_status;`));
		}
		assert.ok(rules.includes("~^:5\\d\\d$     http_status;"));
		assert.match(rules, /default\s+"";/);
		assert.match(logFormat, /"event_type":"\$security_event_type"/);
		assert.match(logFormat, /"severity":"\$security_severity"/);
		assert.match(logFormat, /"remote_port":"\$realip_remote_port"/);
		assert.match(logFormat, /log_format security_json escape=json/);
	});

	it("scopes sensitive log rotation and runs checks at a bounded cadence", () => {
		assert.match(securityLogrotateBlock, /create 0640 npm npm/);
		assert.match(securityLogrotateBlock, /daily/);
		assert.match(securityLogrotateBlock, /maxsize 50M/);
		assert.match(securityLogrotateBlock, /rotate 30/);
		assert.match(securityLogrotateBlock, /compress/);
		assert.match(securityLogrotateBlock, /delaycompress/);
		const errorBlock = logrotate.match(/\/data\/logs\/\*_error\.log[\s\S]*?\n\}/)?.[0] || "";
		assert.doesNotMatch(errorBlock, /delaycompress/);
		assert.match(setup, /1000 \* 60 \* 15; \/\/ every 15 minutes/);
	});
});
