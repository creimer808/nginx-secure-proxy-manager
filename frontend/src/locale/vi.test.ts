import { describe, expect, it } from "vitest";
import en from "./src/en.json";
import vi from "./src/vi.json";

const english = en as Record<string, { defaultMessage: string }>;
const vietnamese = vi as Record<string, { defaultMessage: string }>;

// Brand names, codes and ICU-only strings can stay the same as English.
const allowedIdentical = new Set([
	"certificates.key-type-ecdsa",
	"certificates.key-type-rsa",
	"column.email",
	"column.ssl",
	"lets-encrypt",
	"object.actions-title",
	"streams.tcp",
	"streams.udp",
]);

// Match NSPM's Estonian test policy: upstream coverage remains complete while
// untranslated fork-specific strings use the existing English fallback.
const NSPM_KEY_PREFIXES = [
	"dashboard.metrics.",
	"dashboard.posture.",
	"dashboard.range.",
	"security.",
	"footer.nspm-",
	"footer.upstream-npm",
	"version.app",
	"version.upstream",
];
const isNspmKey = (key: string) => NSPM_KEY_PREFIXES.some((prefix) => key === prefix || key.startsWith(prefix));
const upstreamEnglish = Object.fromEntries(Object.entries(english).filter(([key]) => !isNspmKey(key)));

describe("Vietnamese UI locale", () => {
	it("covers every English UI key", () => {
		const missing = Object.keys(upstreamEnglish).filter((key) => !(key in vietnamese));
		expect(missing).toEqual([]);
	});

	it("does not add keys that are missing from English", () => {
		const extra = Object.keys(vietnamese).filter((key) => !(key in english));
		expect(extra).toEqual([]);
	});

	it("is translated, not an English copy", () => {
		const identical = Object.keys(upstreamEnglish).filter(
			(key) => vietnamese[key]?.defaultMessage === english[key]?.defaultMessage,
		);
		const unexpected = identical.filter((key) => !allowedIdentical.has(key));
		expect(unexpected).toEqual([]);
	});

	it("keeps ICU data placeholders from English strings", () => {
		const argNames = [
			"count",
			"object",
			"objects",
			"id",
			"date",
			"users",
			"rules",
			"max",
			"min",
			"domain",
			"code",
			"latestVersion",
			"name",
		];
		const usedArgs = (message: string) => argNames.filter((name) => message.includes(`{${name}`));
		const broken: string[] = [];

		for (const key of Object.keys(english)) {
			const expected = usedArgs(english[key].defaultMessage).join(",");
			const actual = usedArgs(vietnamese[key]?.defaultMessage ?? "").join(",");
			if (expected !== actual) {
				broken.push(`${key}: expected {${expected}} got {${actual}}`);
			}
		}

		expect(broken).toEqual([]);
	});
});
