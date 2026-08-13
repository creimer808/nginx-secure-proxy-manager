import assert from "node:assert/strict";
import { describe, it } from "node:test";
import knex from "knex";
import errs from "../lib/error.js";
import { applyVisibleEvents, escapeLike, literalSearch, securityAccess, validateEventFilters } from "./security-api.js";

describe("security API validation and visibility", () => {
	it("escapes SQL LIKE wildcard metacharacters", () => {
		assert.equal(escapeLike("a%_\\b"), "a\\%\\_\\\\b");
	});

	it("uses an executable SQLite ESCAPE clause for literal %, _, and backslash searches", async () => {
		const database = knex({ client: "better-sqlite3", connection: { filename: ":memory:" }, useNullAsDefault: true });
		try {
			await database.schema.createTable("event", (table) => { table.increments("id"); table.text("value"); });
			await database("event").insert([{ value: "token%value" }, { value: "tokenXvalue" }, { value: "under_score" }, { value: "underXscore" }, { value: "path\\name" }]);
			for (const [term, expected] of [["%", ["token%value"]], ["_", ["under_score"]], ["\\", ["path\\name"]]]) {
				const rows = await literalSearch(database("event"), "value", term).select("value").orderBy("id");
				assert.deepEqual(rows.map((row) => row.value), expected);
			}
		} finally { await database.destroy(); }
	});

	it("applies current proxy-host visibility and excludes orphaned events for non-admin actors", () => {
		const calls = [];
		const query = { leftJoin: (...args) => { calls.push(["join", ...args]); return query; }, whereNotNull: (...args) => { calls.push(["notNull", ...args]); return query; }, andWhere: (...args) => { calls.push(["where", ...args]); return query; } };
		applyVisibleEvents(query, { admin: false, visibility: "user", userId: 8 });
		assert.deepEqual(calls, [["join", "proxy_host as p", "p.id", "e.proxy_host_id"], ["notNull", "e.proxy_host_id"], ["where", "p.is_deleted", 0], ["where", "p.owner_user_id", 8]]);
	});

	it("uses the access contract for visibility=all and hidden permission failures", async () => {
		const all = await securityAccess({ can: async () => ({ roles: ["user"], permission_visibility: "all" }), token: { getUserId: () => 4 } }, "security:events-list");
		assert.deepEqual(all, { admin: false, visibility: "all", userId: 4 });
		await assert.rejects(() => securityAccess({ can: async () => { throw new errs.PermissionError(); }, token: { getUserId: () => 4 } }, "security:events-list"), { status: 403 });
	});

	it("rejects malformed IDs, paths, cursors, ranges, and filters", () => {
		for (const input of [
			{ limit: "201" }, { cursor: "not-a-cursor" }, { client_ip: "not-an-ip" }, { proxy_host_id: "0" }, { event_type: "unknown" }, { from: "bad" }, { query: "x", from: "0", to: String(25 * 60 * 60 * 1000) }, { path: "../../etc/passwd" }, { status_class: "4xx" }, { status: "500", status_class: "5xx" },
		]) assert.throws(() => validateEventFilters(input), { status: 400 });
	});

	it("accepts a 5xx status-class drilldown without treating it as one status", () => {
		const filters = validateEventFilters({ status_class: "5xx" });
		assert.equal(filters.status, null);
		assert.equal(filters.statusClass, "5xx");
	});
});
