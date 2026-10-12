import fs from "node:fs";
import path from "node:path";
import signale from "signale";
import { isDebugMode } from "./lib/config.js";

const opts = {
	logLevel: "info",
};

const createLogger = (scope) => withFileSink(new signale.Signale({ scope, ...opts }), scope);

const global = createLogger("Global   ");
const migrate = createLogger("Migrate  ");
const express = createLogger("Express  ");
const access = createLogger("Access   ");
const nginx = createLogger("Nginx    ");
const ssl = createLogger("SSL      ");
const certbot = createLogger("Certbot  ");
const importer = createLogger("Importer ");
const setup = createLogger("Setup    ");
const ipRanges = createLogger("IP Ranges");
const remoteVersion = createLogger("Remote Version");
const trafficMetrics = createLogger("Traffic ");

const debug = (logger, ...args) => {
	if (isDebugMode()) {
		logger.debug(...args);
	}
};

export { debug, global, migrate, express, access, nginx, ssl, certbot, importer, setup, ipRanges, remoteVersion, trafficMetrics };
