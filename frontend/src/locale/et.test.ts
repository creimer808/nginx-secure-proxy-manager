import { describe, expect, it } from "vitest";
import en from "./src/en.json";
import et from "./src/et.json";

const english = en as Record<string, { defaultMessage: string }>;
const estonian = et as Record<string, { defaultMessage: string }>;

// Brand names, codes and ICU-only strings can stay the same as English.
const allowedIdentical = new Set([
	"certificates.key-type-ecdsa",
	"certificates.key-type-rsa",
	"column.ssl",
	"lets-encrypt",
	"object.actions-title",
	"streams.tcp",
	"streams.udp",
]);

// NSPM fork keys follow the repo's locale policy (see check-locales.cjs): `en`
// is the source of truth and the other locales are legitimately incomplete, so
// fork-specific keys fall back to English until someone translates them. The
// upstream completeness guarantees below are scoped to the upstream key
// namespace and deliberately do not force fork keys to be translated.
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

describe("Estonian UI locale", () => {
	it("covers every English UI key", () => {
		const missing = Object.keys(upstreamEnglish).filter((key) => !(key in estonian));
		expect(missing).toEqual([]);
	});

	it("does not add keys that are missing from English", () => {
		const extra = Object.keys(estonian).filter((key) => !(key in english));
		expect(extra).toEqual([]);
	});

	it("is translated, not an English copy", () => {
		const identical = Object.keys(upstreamEnglish).filter(
			(key) => estonian[key]?.defaultMessage === english[key]?.defaultMessage,
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
			const actual = usedArgs(estonian[key]?.defaultMessage ?? "").join(",");
			if (expected !== actual) {
				broken.push(`${key}: expected {${expected}} got {${actual}}`);
			}
		}

		expect(broken).toEqual([]);
	});
});
