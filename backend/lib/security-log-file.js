import fs from "node:fs";
import { resolve } from "node:path";

const DEFAULT_LOG_DIR = process.env.SECURITY_LOG_DIR || "/data/logs";
const SECURITY_LOG_MODE = 0o640;

const getSecurityLogPath = (proxyHostId, logDir = DEFAULT_LOG_DIR) => {
	if (!Number.isSafeInteger(proxyHostId) || proxyHostId < 1) {
		throw new Error("Invalid proxy host id for security log");
	}

	const resolvedLogDir = resolve(logDir);
	const logPath = resolve(resolvedLogDir, `proxy-host-${proxyHostId}_security.log`);
	if (!logPath.startsWith(`${resolvedLogDir}/`)) {
		throw new Error("Security log path escaped the log directory");
	}
	return { logPath, resolvedLogDir };
};

/**
 * Creates or corrects the per-host security log before Nginx is configured to
 * write sensitive request metadata to it. The log directory and file must be
 * regular filesystem entries; symlinks are rejected rather than followed.
 *
 * The backend normally runs as the `npm` user, so using its uid/gid ensures a
 * newly created file has the same ownership Nginx uses. A caller without
 * permission to correct ownership fails closed instead of activating logging
 * with a broader or unknown owner.
 *
 * @param {number} proxyHostId
 * @param {{logDir?: string}} [options]
 * @returns {string} absolute log file path
 */
const ensureSecurityLogFile = (proxyHostId, options = {}) => {
	const { logPath, resolvedLogDir } = getSecurityLogPath(proxyHostId, options.logDir);

	fs.mkdirSync(resolvedLogDir, { recursive: true, mode: 0o750 });
	const dirStat = fs.lstatSync(resolvedLogDir);
	if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
		throw new Error("Security log directory must be a non-symlink directory");
	}
	if (fs.realpathSync(resolvedLogDir) !== resolvedLogDir) {
		throw new Error("Security log directory must not resolve through a symlink");
	}

	const flags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW;
	let descriptor;
	try {
		descriptor = fs.openSync(logPath, flags, SECURITY_LOG_MODE);
	} catch (err) {
		if (err.code === "ELOOP") throw new Error("Security log file must be a regular non-symlink file");
		throw err;
	}
	try {
		const fileStat = fs.fstatSync(descriptor);
		if (!fileStat.isFile() || fileStat.nlink !== 1) {
			throw new Error("Security log file must be a regular non-linked file");
		}
		fs.fchmodSync(descriptor, SECURITY_LOG_MODE);
		if (typeof process.getuid === "function" && typeof process.getgid === "function") {
			const uid = process.getuid();
			const gid = process.getgid();
			if (fileStat.uid !== uid || fileStat.gid !== gid) fs.fchownSync(descriptor, uid, gid);
		}
	} finally {
		fs.closeSync(descriptor);
	}

	return logPath;
};

export { DEFAULT_LOG_DIR, SECURITY_LOG_MODE, ensureSecurityLogFile, getSecurityLogPath };
