import { migrate as logger } from "../logger.js";

const migrateName = "security_events";

/**
 * Detailed security-event storage deliberately avoids database enums and JSON
 * indexes so SQLite, MySQL, and PostgreSQL use the same schema.
 *
 * @param {import("knex").Knex} knex
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	await knex.schema.createTable("security_event", (table) => {
		table.increments().primary();
		table.bigInteger("occurred_at_ms").notNull();
		table.dateTime("created_on").notNull();
		table.integer("proxy_host_id").unsigned().nullable();
		table.text("host_domain_snapshot").nullable();
		table.integer("owner_user_id_snapshot").unsigned().nullable();
		table.string("source_kind", 32).notNull();
		table.string("schema_version", 16).nullable();
		table.string("ruleset_version", 64).nullable();
		table.string("event_id", 128).nullable();
		table.string("request_id", 128).nullable();
		table.string("event_type", 32).notNull();
		table.string("severity", 16).notNull();
		table.string("rule_id", 128).nullable();
		table.string("rule_category", 64).nullable();
		table.string("rule_action", 32).nullable();
		table.string("client_ip", 45).nullable();
		table.string("peer_ip", 45).nullable();
		table.integer("peer_port").unsigned().nullable();
		table.string("method", 16).nullable();
		table.string("scheme", 16).nullable();
		table.text("request_host").nullable();
		table.text("request_uri", "longtext").nullable();
		table.string("http_protocol", 16).nullable();
		table.integer("status").unsigned().nullable();
		table.string("upstream_status", 128).nullable();
		table.bigInteger("request_bytes").unsigned().nullable();
		table.bigInteger("response_bytes").unsigned().nullable();
		table.bigInteger("request_time_ms").unsigned().nullable();
		table.text("upstream_addr").nullable();
		table.bigInteger("upstream_time_ms").unsigned().nullable();
		table.string("tls_protocol", 32).nullable();
		table.text("tls_cipher").nullable();
		table.text("remote_user").nullable();
		table.text("user_agent", "longtext").nullable();
		table.text("referrer", "longtext").nullable();
		table.string("nginx_error_level", 32).nullable();
		table.text("nginx_error_message", "longtext").nullable();
		table.string("ingest_segment_id", 128).notNull();
		table.bigInteger("ingest_line_offset").notNull();
		table.unique(["event_id"]);
		table.unique(["ingest_segment_id", "ingest_line_offset"]);
		table.index(["occurred_at_ms", "id"]);
		table.index(["proxy_host_id", "occurred_at_ms", "id"]);
		table.index(["client_ip", "occurred_at_ms"]);
		table.index(["rule_id", "occurred_at_ms"]);
		table.index(["event_type", "occurred_at_ms"]);
		table.index(["status", "occurred_at_ms"]);
	});

	await knex.schema.createTable("security_log_cursor", (table) => {
		table.increments().primary();
		table.string("segment_id", 128).notNull();
		table.string("file_key", 128).notNull();
		table.text("file_path").notNull();
		table.string("log_kind", 32).notNull();
		table.bigInteger("byte_offset").notNull().unsigned().defaultTo(0);
		table.string("content_fingerprint", 128).notNull();
		table.dateTime("updated_on").notNull();
		table.unique(["segment_id", "log_kind"]);
		table.index(["updated_on"]);
	});

	await knex.schema.createTable("security_collector_state", (table) => {
		table.increments().primary();
		table.dateTime("last_started_on").nullable();
		table.dateTime("last_completed_on").nullable();
		table.dateTime("last_error_on").nullable();
		table.string("last_error_summary", 512).nullable();
		table.bigInteger("bytes_read").notNull().unsigned().defaultTo(0);
		table.bigInteger("lines_read").notNull().unsigned().defaultTo(0);
		table.bigInteger("events_inserted").notNull().unsigned().defaultTo(0);
		// Conservative fallback when a driver-native database-size query is unavailable.
		table.bigInteger("estimated_database_bytes").notNull().unsigned().defaultTo(0);
		table.bigInteger("malformed_lines").notNull().unsigned().defaultTo(0);
		table.bigInteger("files_pending").notNull().unsigned().defaultTo(0);
		table.boolean("limit_reached").notNull().defaultTo(false);
		table.boolean("database_high_water_reached").notNull().defaultTo(false);
		table.boolean("raw_log_disk_high_water_reached").notNull().defaultTo(false);
	});
	logger.info(`[${migrateName}] security event tables created`);
};

/** @param {import("knex").Knex} knex */
const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	await knex.schema.dropTableIfExists("security_collector_state");
	await knex.schema.dropTableIfExists("security_log_cursor");
	await knex.schema.dropTableIfExists("security_event");
};

export { up, down };
