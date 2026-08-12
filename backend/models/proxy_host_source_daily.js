// Objection Docs:
// http://vincit.github.io/objection.js/

import { Model } from "objection";
import db from "../db.js";

Model.knex(db());

class ProxyHostSourceDaily extends Model {
	static get name() {
		return "ProxyHostSourceDaily";
	}

	static get tableName() {
		return "proxy_host_source_daily";
	}
}

export default ProxyHostSourceDaily;
