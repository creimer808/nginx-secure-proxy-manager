import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, it } from "node:test";

let nginx;
let directory;
let database;
before(async () => {
	directory = fs.mkdtempSync(path.join(os.tmpdir(), "nginx-render-sync-"));
	process.env.NODE_ENV = "test";
	process.env.DB_SQLITE_FILE = path.join(directory, "test.sqlite");
	process.env.NODE_CONFIG_DIR = directory;
	process.env.NSPM_KEYS_FILE = path.join(directory, "keys.json");
	nginx = (await import("./nginx.js")).default;
	database = (await import("../db.js")).default();
	await database.schema.createTable("access_list", (table) => {
		table.increments("id");
		table.integer("is_deleted").defaultTo(0);
	});
});
after(async () => {
	await database.destroy();
	fs.rmSync(directory, { recursive: true, force: true });
});

it("fails closed for a missing host access list without losing security logging", async () => {
	const host = {
		id: 1,
		enabled: true,
		domain_names: ["example.test"],
		forward_scheme: "http",
		forward_host: "127.0.0.1",
		forward_port: 8080,
		certificate_id: 0,
		access_list_id: 999,
		locations: [],
	};
	const original = structuredClone(host);
	const rendered = await nginx.renderConfig("proxy_host", host);
	assert.match(rendered, /deny all;/);
	assert.match(rendered, /proxy-host-1_security\.log security_json/);
	assert.deepEqual(host, original);
});

it("rejects stored directive injection through NSPM's shared render path", async () => {
	await assert.rejects(
		nginx.renderConfig("stream", {
			id: 1,
			incoming_port: 9000,
			forwarding_host: "127.0.0.1; include /untrusted.conf",
			forwarding_port: 9001,
			tcp_forwarding: true,
		}),
		(error) => error.unsafeNginxValue === true,
	);
});
