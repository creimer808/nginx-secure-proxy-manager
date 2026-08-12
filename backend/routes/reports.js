import express from "express";
import internalReport from "../internal/report.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

router
	.route("/hosts")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /reports/hosts
	 */
	.get(async (req, res, next) => {
		try {
			const data = await internalReport.getHostsReport(res.locals.access);
			res.status(200).send(data);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

router
	.route("/dashboard")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /reports/dashboard?range=24h|7d|30d
	 *
	 * The response may contain raw client IP addresses, so it is never cached.
	 */
	.get(async (req, res, next) => {
		try {
			const range = req.query.range;
			const data = await internalReport.getDashboardReport(res.locals.access, range);
			// Override the global no-cache header: raw IPs must not be stored by shared caches.
			res.set("Cache-Control", "private, no-store");
			res.status(200).send(data);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
