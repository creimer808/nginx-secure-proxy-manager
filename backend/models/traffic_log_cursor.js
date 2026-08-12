// Objection Docs:
// http://vincit.github.io/objection.js/

import { Model } from "objection";
import db from "../db.js";

Model.knex(db());

class TrafficLogCursor extends Model {
	static get name() {
		return "TrafficLogCursor";
	}

	static get tableName() {
		return "traffic_log_cursor";
	}
}

export default TrafficLogCursor;
