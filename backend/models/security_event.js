import { Model } from "objection";
import db from "../db.js";

Model.knex(db());

class SecurityEvent extends Model {
	static get name() {
		return "SecurityEvent";
	}

	static get tableName() {
		return "security_event";
	}
}

export default SecurityEvent;
