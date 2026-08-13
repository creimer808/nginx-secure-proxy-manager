import { deepStrictEqual, strictEqual, throws } from "node:assert";
import { describe, it } from "node:test";
import { parseVersion, resolveVersions, versionResponse } from "./version.js";

const packageMetadata = { version: "0.1.2", upstreamVersion: "2.15.1" };

describe("version metadata", () => {
	it("parses strict semantic versions", () => {
		deepStrictEqual(parseVersion("2.15.1"), { normalized: "2.15.1", major: 2, minor: 15, revision: 1 });
	});

	it("rejects malformed versions", () => {
		for (const value of ["2.15", "v2.15.1", "2.15.1-custom", "2.15.01", ""])
			throws(() => parseVersion(value), /Invalid/);
	});

	it("uses sealed package metadata instead of runtime environment values", () => {
		const versions = resolveVersions(packageMetadata);
		strictEqual(versions.app.normalized, "0.1.2");
		strictEqual(versions.upstream.normalized, "2.15.1");
	});

	it("keeps the health version object compatible with upstream API consumers", () => {
		deepStrictEqual(versionResponse(packageMetadata), {
			version: { major: 2, minor: 15, revision: 1 },
			app_version: "0.1.2",
			upstream_version: "2.15.1",
		});
	});
});
