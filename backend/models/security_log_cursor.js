import { Model } from "objection";
import db from "../db.js";

Model.knex(db());

class SecurityLogCursor extends Model {
	static get name() {
		return "SecurityLogCursor";
	}

	static get tableName() {
		return "security_log_cursor";
	}
}

export default SecurityLogCursor;
