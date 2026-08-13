import express from "express";
import { debug, express as logger } from "../logger.js";
import { resolveVersions } from "../lib/version.js";
import { getCompiledSchema } from "../schema/index.js";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})

	/**
	 * GET /schema
	 */
	.get(async (req, res, next) => {
		try {
			const swaggerJSON = await getCompiledSchema();

			let proto = req.protocol;
			if (typeof req.headers["x-forwarded-proto"] !== "undefined" && req.headers["x-forwarded-proto"]) {
				proto = req.headers["x-forwarded-proto"];
			}

			let origin = `${proto}://${req.hostname}`;
			if (typeof req.headers.origin !== "undefined" && req.headers.origin) {
				origin = req.headers.origin;
			}

			swaggerJSON.info.version = resolveVersions().app.normalized;
			swaggerJSON.servers[0].url = `${origin}/api`;
			res.status(200).send(swaggerJSON);
		} catch (err) {
			debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err}`);
			next(err);
		}
	});

export default router;
