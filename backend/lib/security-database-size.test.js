import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { databaseStorageBytes } from "./security-database-size.js";

describe("security database size measurement", () => {
	it("reads PostgreSQL result rows instead of response metadata", async () => {
		const database = {
			client: { config: { client: "pg" } },
			raw: async () => ({ command: "SELECT", rowCount: 1, rows: [{ bytes: "987654" }] }),
		};
		assert.equal(await databaseStorageBytes(database), 987654);
	});

	it("returns null when a native result has no byte value", async () => {
		const database = {
			client: { config: { client: "pg" } },
			raw: async () => ({ command: "SELECT", rowCount: 1, rows: [] }),
		};
		assert.equal(await databaseStorageBytes(database), null);
	});
});
