import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { RULESET_VERSION, SECURITY_RULES } from "./security-rule-catalog.js";

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

const securityLogrotateBlock = logrotate.match(/\/data\/logs\/\*_security\.log \{[\s\S]*?\n\}/)?.[0] || "";

/**
 * Nginx is the only thing that actually detects. The JavaScript catalog exists
 * so the API can validate a rule_id and serve a rule list, which makes it a
 * duplicate of the .conf and therefore free to drift. These helpers parse the
 * .conf so the drift becomes a test failure instead of a wrong rule catalog.
 */
const mapBody = (targetVariable) => {
	const match = new RegExp(`map\\s+\\S+\\s+\\$${targetVariable}\\s*\\{([\\s\\S]*?)\\n\\}`).exec(rules);
	assert.ok(match, `security-rules.conf defines no map for $${targetVariable}`);
	return match[1];
};
/** Rule ids are the map *values*: the token immediately before the terminating semicolon. */
const ruleIdsIn = (body) => (body.match(/([a-z][a-z0-9-]*\.[a-z0-9-]+);/g) || []).map((entry) => entry.slice(0, -1));
/** `~^sql\.  sql;` => sql -> sql */
const categoryByPrefix = new Map(
	[...mapBody("security_rule_category").matchAll(/~\^([a-z0-9]+)\\\.\s+([a-z-]+);/g)].map((match) => [match[1], match[2]]),
);

describe("security attribution Nginx contract", () => {
	it("keeps the JavaScript rule catalog identical to the Nginx ruleset", () => {
		const detected = [...new Set([...ruleIdsIn(mapBody("security_query_rule_id")), ...ruleIdsIn(mapBody("security_user_agent_rule_id"))])];
		assert.deepEqual(detected.slice().sort(), SECURITY_RULES.map((rule) => rule.id).sort(), "rule ids differ between security-rules.conf and security-rule-catalog.js");

		// A rule whose prefix has no category entry silently logs an empty
		// category, which is invisible until someone tries to filter by it.
		for (const rule of SECURITY_RULES) {
			const prefix = rule.id.split(".")[0];
			assert.equal(categoryByPrefix.get(prefix), rule.category, `rule ${rule.id} is categorised as ${categoryByPrefix.get(prefix)} by Nginx but ${rule.category} by the catalog`);
		}
	});

	it("stamps the catalog's ruleset version into every record", () => {
		assert.ok(logFormat.includes(`"ruleset_version":"${RULESET_VERSION}"`), `log-proxy.conf must stamp ruleset_version ${RULESET_VERSION}`);
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
		assert.match(block, /if \(\$security_blocking_rule_id != ""\) \{\s*return 403;/);
		assert.match(defaultConfig, /include conf\.d\/include\/block-exploits\.conf;/);
		assert.match(template, /set \$security_exploit_protection_enabled/);
	});

	it("detects on every host but blocks only opted-in hosts, and only with legacy rules", () => {
		// Enforcement must never read the ungated id: that variable now carries
		// detect-only rules whose whole point is that they change no response.
		const blockDirectives = block.replace(/^\s*#.*$/gm, "");
		assert.doesNotMatch(blockDirectives, /\$security_rule_id\b/, "block-exploits.conf must gate on $security_blocking_rule_id");
		assert.match(mapBody("security_rule_id"), /default \$security_detected_rule_id;/, "attribution must not be gated on the blocking switch");

		// Only a blockable rule on an opted-in host resolves to a blocking id.
		assert.match(mapBody("security_blocking_rule_id"), /~\^1:1:\(\.\+\)\$\s+\$1;/);

		const blockable = mapBody("security_rule_blockable");
		const blockablePrefixes = new Set([...blockable.matchAll(/~\^([a-z0-9]+)\\\.\s+1;/g)].map((match) => match[1]));
		for (const rule of SECURITY_RULES) {
			const prefix = rule.id.split(".")[0];
			const permitted = blockablePrefixes.has(prefix);
			assert.equal(permitted, rule.action === "block", `rule ${rule.id} is action=${rule.action} in the catalog but ${permitted ? "" : "not "}blockable in Nginx`);
		}
		// A prefix is the unit of blockability, so a detect-only rule must never
		// share a prefix with a blocking one.
		for (const rule of SECURITY_RULES) {
			const siblings = SECURITY_RULES.filter((other) => other.id.split(".")[0] === rule.id.split(".")[0]);
			assert.equal(new Set(siblings.map((other) => other.action)).size, 1, `prefix ${rule.id.split(".")[0]} mixes blocking and detect-only rules`);
		}
	});

	it("does not let a detect-only match outrank an enforcement action", () => {
		const severity = mapBody("security_severity");
		assert.match(severity, /~\^block:\s+high;/);
		assert.match(severity, /~\^detect:\s+medium;/);
		const action = mapBody("security_rule_action");
		assert.match(action, /~\^:\s+"";/, "no rule match must produce no action");
		assert.match(action, /~:1:1\$\s+block;/);
		assert.match(action, /default\s+detect;/);
	});

	it("records the traffic that never reaches a proxy host", () => {
		// The default server blocks exploits and returns 403. Without its own
		// security log every unknown-Host hit and raw-IP scan is discarded.
		assert.match(defaultConfig, /access_log \/data\/logs\/fallback_security\.log security_json if=\$security_log_enabled;/);
		for (const file of ["backend/templates/default.conf", "backend/templates/redirection_host.conf", "backend/templates/dead_host.conf"]) {
			assert.match(read(file), /access_log \/data\/logs\/fallback_security\.log security_json if=\$security_log_enabled;/);
		}
		// The fallback record carries no proxy host id, which is what keeps it
		// administrator-only under the existing visibility guard.
		assert.doesNotMatch(defaultConfig, /set \$security_proxy_host_id/);
		assert.match(securityLogrotateBlock, /\/data\/logs\/\*_security\.log/);
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
