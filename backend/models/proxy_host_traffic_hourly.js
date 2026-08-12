// Objection Docs:
// http://vincit.github.io/objection.js/

import { Model } from "objection";
import db from "../db.js";

Model.knex(db());

class ProxyHostTrafficHourly extends Model {
	static get name() {
		return "ProxyHostTrafficHourly";
	}

	static get tableName() {
		return "proxy_host_traffic_hourly";
	}
}

export default ProxyHostTrafficHourly;
