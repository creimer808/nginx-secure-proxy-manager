import express from "express";
import { getEvent, getRetention, listEvents, listLogFiles, overview, readLog, rules, updateRetention } from "../internal/security-api.js";
import jwtdecode from "../lib/express/jwt-decode.js";
import { debug, express as logger } from "../logger.js";

const router = express.Router({ caseSensitive: true, strict: true, mergeParams: true });
const securityResponseHeaders = {
	"Cache-Control": "private, no-store",
	"X-Content-Type-Options": "nosniff",
	"Referrer-Policy": "no-referrer",
};
const secureHeaders = (_, res, next) => { res.set(securityResponseHeaders); next(); };
const handler = (fn) => async (req, res, next) => {
	try { res.status(200).send(await fn(req, res)); } catch (err) { debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err.status || 500}`); next(err); }
};
router.use(jwtdecode());
router.use(secureHeaders);
router.route("/overview").options((_, res) => res.sendStatus(204)).get(handler((req, res) => overview(res.locals.access, req.query.range)));
router.route("/events").options((_, res) => res.sendStatus(204)).get(handler((req, res) => listEvents(res.locals.access, req.query)));
router.route("/events/:event_id").options((_, res) => res.sendStatus(204)).get(handler((req, res) => getEvent(res.locals.access, req.params.event_id)));
router.route("/rules").options((_, res) => res.sendStatus(204)).get(handler((req, res) => rules(res.locals.access, req.query.range)));
router.route("/log-files").options((_, res) => res.sendStatus(204)).get(handler((req, res) => listLogFiles(res.locals.access, req.query)));
router.route("/logs").options((_, res) => res.sendStatus(204)).get(handler((req, res) => readLog(res.locals.access, req.query, () => req.destroyed || res.destroyed)));
router.route("/settings").options((_, res) => res.sendStatus(204)).get(handler((_, res) => getRetention(res.locals.access))).put(async (req, res, next) => { try { res.status(200).send(await updateRetention(res.locals.access, req.body?.retention_days)); } catch (err) { debug(logger, `${req.method.toUpperCase()} ${req.path}: ${err.status || 500}`); next(err); } });
export { securityResponseHeaders };
export default router;
