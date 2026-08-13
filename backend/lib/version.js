import pjson from "../package.json" with { type: "json" };

const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

export const parseVersion = (value, label = "version") => {
	if (typeof value !== "string" || !SEMVER.test(value.trim())) {
		throw new Error(`Invalid ${label}: expected major.minor.patch`);
	}
	const normalized = value.trim();
	const [major, minor, revision] = normalized.split(".").map(Number);
	return { normalized, major, minor, revision };
};

// Package metadata is baked into a release image. Do not trust mutable runtime
// environment variables for the version users use to identify that release.
export const resolveVersions = (packageMetadata = pjson) => ({
	app: parseVersion(packageMetadata.version, "NSPM application version"),
	upstream: parseVersion(packageMetadata.upstreamVersion, "upstream Nginx Proxy Manager version"),
});

export const versionResponse = (packageMetadata = pjson) => {
	const { app, upstream } = resolveVersions(packageMetadata);
	return {
		// Retained for existing API clients that expect NPM-compatible version fields.
		version: { major: upstream.major, minor: upstream.minor, revision: upstream.revision },
		app_version: app.normalized,
		upstream_version: upstream.normalized,
	};
};
