import { Model } from "objection";
import db from "../db.js";

Model.knex(db());

class SecurityCollectorState extends Model {
	static get name() {
		return "SecurityCollectorState";
	}

	static get tableName() {
		return "security_collector_state";
	}
}

export default SecurityCollectorState;
