import { migrate as logger } from "../logger.js";

const migrateName = "security_telemetry_progress";

/**
 * Adds the state the collector needs to make guaranteed forward progress:
 * a round-robin resume pointer, and the file size each stored fingerprint
 * covers so an unchanged file is never re-hashed. Also records the outcome of
 * the startup proxy-host configuration upgrade so an operator can see that
 * security logging is inactive without reading container logs.
 *
 * @param {import("knex").Knex} knex
 */
const up = async (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	await knex.schema.alterTable("security_collector_state", (table) => {
		table.integer("last_host_id").nullable();
		table.integer("last_candidate_index").nullable();
	});

	await knex.schema.alterTable("security_log_cursor", (table) => {
		table.bigInteger("fingerprint_size").notNull().unsigned().defaultTo(0);
	});

	await knex.schema.createTable("security_config_state", (table) => {
		table.increments().primary();
		table.dateTime("last_run_on").nullable();
		table.integer("hosts_total").notNull().unsigned().defaultTo(0);
		table.integer("hosts_upgraded").notNull().unsigned().defaultTo(0);
		table.integer("hosts_skipped").notNull().unsigned().defaultTo(0);
		table.integer("hosts_pending").notNull().unsigned().defaultTo(0);
		table.boolean("reload_deferred").notNull().defaultTo(false);
		table.string("last_error_summary", 512).nullable();
	});

	logger.info(`[${migrateName}] security telemetry progress state created`);
};

/** @param {import("knex").Knex} knex */
const down = async (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);
	await knex.schema.dropTableIfExists("security_config_state");
	await knex.schema.alterTable("security_log_cursor", (table) => {
		table.dropColumn("fingerprint_size");
	});
	await knex.schema.alterTable("security_collector_state", (table) => {
		table.dropColumn("last_host_id");
		table.dropColumn("last_candidate_index");
	});
};

export { up, down };
