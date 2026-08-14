/**
 * The canonical catalog of built-in security rules.
 *
 * Detection itself lives in Nginx, at HTTP scope, in
 * docker/rootfs/etc/nginx/conf.d/include/security-rules.conf. This file is the
 * JavaScript half of that contract: it names the same rules so the API can
 * validate a rule_id filter and serve a rule catalog without shelling out to
 * Nginx.
 *
 * The two halves are bound by security-nginx-contract.test.js, which parses the
 * .conf and asserts this list matches it exactly. Adding a rule in one place and
 * not the other is a test failure, not a silent drift.
 *
 * `action` records what a match does, and is deliberately not uniform:
 *   block  - legacy signatures inherited from upstream's block-exploits.conf.
 *            These return 403 when the host enables Block Common Exploits.
 *   detect - attribution only. Never changes the response. Every rule added
 *            after the upstream inheritance is detect-only, because a false
 *            positive on a path like /actuator would take a working site down.
 */

const RULE_ACTION_BLOCK = "block";
const RULE_ACTION_DETECT = "detect";

/**
 * Bumped whenever the rules or their semantics change. Nginx stamps this into
 * every record via the security_json log format, so an event can always be read
 * against the ruleset that produced it. The .conf carries the same literal and
 * the contract test keeps the two in step.
 */
const RULESET_VERSION = "2026-08-13";

/** @type {{id: string, category: string, action: string, description: string}[]} */
const SECURITY_RULES = [
	// --- Legacy upstream signatures. These block. Do not add to this group. ---
	{ id: "sql.union-select", category: "sql", action: RULE_ACTION_BLOCK, description: "Built-in SQL union/select signature" },
	{ id: "sql.union-all-select", category: "sql", action: RULE_ACTION_BLOCK, description: "Built-in SQL union-all-select signature" },
	{ id: "sql.concat", category: "sql", action: RULE_ACTION_BLOCK, description: "Built-in SQL concat signature" },
	{ id: "file.remote-url-parameter", category: "file", action: RULE_ACTION_BLOCK, description: "Remote URL parameter" },
	{ id: "file.path-traversal", category: "file", action: RULE_ACTION_BLOCK, description: "Path traversal parameter" },
	{ id: "file.absolute-path", category: "file", action: RULE_ACTION_BLOCK, description: "Absolute-path parameter" },
	{ id: "common.script-tag", category: "common", action: RULE_ACTION_BLOCK, description: "Script-tag parameter" },
	{ id: "php.globals", category: "common", action: RULE_ACTION_BLOCK, description: "PHP GLOBALS parameter" },
	{ id: "php.request", category: "common", action: RULE_ACTION_BLOCK, description: "PHP REQUEST parameter" },
	{ id: "lfi.proc-self-environ", category: "common", action: RULE_ACTION_BLOCK, description: "Local file inclusion signature" },
	{ id: "joomla.mosconfig", category: "common", action: RULE_ACTION_BLOCK, description: "Joomla mosConfig signature" },
	{ id: "php.base64-code", category: "common", action: RULE_ACTION_BLOCK, description: "PHP base64 code signature" },
	{ id: "spam.keyword-group-1", category: "spam", action: RULE_ACTION_BLOCK, description: "Spam keyword group 1" },
	{ id: "spam.keyword-group-2", category: "spam", action: RULE_ACTION_BLOCK, description: "Spam keyword group 2" },
	{ id: "spam.keyword-group-3", category: "spam", action: RULE_ACTION_BLOCK, description: "Spam keyword group 3" },
	{ id: "spam.keyword-group-4", category: "spam", action: RULE_ACTION_BLOCK, description: "Spam keyword group 4" },
	{ id: "ua.indy-library", category: "user-agent", action: RULE_ACTION_BLOCK, description: "Indy Library user agent" },
	{ id: "ua.libwww-perl", category: "user-agent", action: RULE_ACTION_BLOCK, description: "libwww-perl user agent" },
	{ id: "ua.getright", category: "user-agent", action: RULE_ACTION_BLOCK, description: "GetRight user agent" },
	{ id: "ua.getweb", category: "user-agent", action: RULE_ACTION_BLOCK, description: "GetWeb user agent" },
	{ id: "ua.gozilla", category: "user-agent", action: RULE_ACTION_BLOCK, description: "Go!Zilla user agent" },
	{ id: "ua.download-demon", category: "user-agent", action: RULE_ACTION_BLOCK, description: "Download Demon user agent" },
	{ id: "ua.go-ahead-got-it", category: "user-agent", action: RULE_ACTION_BLOCK, description: "Go-Ahead-Got-It user agent" },
	{ id: "ua.turnitinbot", category: "user-agent", action: RULE_ACTION_BLOCK, description: "TurnitinBot user agent" },
	{ id: "ua.grabnet", category: "user-agent", action: RULE_ACTION_BLOCK, description: "GrabNet user agent" },
];

/** Every rule prefix the parser and API will accept, derived rather than restated. */
const RULE_ID_PREFIXES = [...new Set(SECURITY_RULES.map((rule) => rule.id.split(".")[0]))];
const RULE_IDS = new Set(SECURITY_RULES.map((rule) => rule.id));
const BLOCKING_RULE_IDS = new Set(SECURITY_RULES.filter((rule) => rule.action === RULE_ACTION_BLOCK).map((rule) => rule.id));

export { BLOCKING_RULE_IDS, RULE_ACTION_BLOCK, RULE_ACTION_DETECT, RULE_ID_PREFIXES, RULE_IDS, RULESET_VERSION, SECURITY_RULES };
