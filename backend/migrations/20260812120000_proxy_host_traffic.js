import { migrate as logger } from "../logger.js";

const migrateName = "proxy_host_traffic";

/**
 * Migrate
 *
 * Adds three aggregate tables for the Security & Traffic dashboard.
 *
 * Design notes:
 * - Integer UTC epoch buckets avoid SQLite/MySQL/PostgreSQL date-function differences.
 * - No foreign keys to proxy_host: hosts are soft-deleted, and the reporting query
 *   joins to active hosts for authorization instead of relying on cascading deletes.
 *
 * @see http://knexjs.org/#Schema
 *
 * @param   {import("knex").Knex}  knex
 * @returns {Promise}
 */
const up = (knex) => {
	logger.info(`[${migrateName}] Migrating Up...`);

	return knex.schema
		.createTable("proxy_host_traffic_hourly", (table) => {
			table.increments().primary();
			table.integer("proxy_host_id").notNull().unsigned();
			// UTC epoch seconds aligned to the start of an hour.
			table.bigInteger("bucket_start").notNull().unsigned();
			table.bigInteger("request_count").notNull().unsigned().defaultTo(0);
			table.bigInteger("status_1xx").notNull().unsigned().defaultTo(0);
			table.bigInteger("status_2xx").notNull().unsigned().defaultTo(0);
			table.bigInteger("status_3xx").notNull().unsigned().defaultTo(0);
			table.bigInteger("status_4xx").notNull().unsigned().defaultTo(0);
			table.bigInteger("status_5xx").notNull().unsigned().defaultTo(0);
			table.bigInteger("bytes_sent").notNull().unsigned().defaultTo(0);
			table.unique(["proxy_host_id", "bucket_start"]);
			table.index(["bucket_start"]);
			table.index(["proxy_host_id", "bucket_start"]);
		})
		.then(() => {
			logger.info(`[${migrateName}] proxy_host_traffic_hourly Table created`);

			return knex.schema.createTable("proxy_host_source_daily", (table) => {
				table.increments().primary();
				table.integer("proxy_host_id").notNull().unsigned();
				// UTC epoch seconds aligned to the start of a day.
				table.bigInteger("bucket_start").notNull().unsigned();
				// Raw observed client IP. IPv4 or IPv6 only (validated on ingest).
				table.string("client_ip", 45).notNull();
				table.bigInteger("status_4xx").notNull().unsigned().defaultTo(0);
				table.bigInteger("status_5xx").notNull().unsigned().defaultTo(0);
				table.bigInteger("observed_count").notNull().unsigned().defaultTo(0);
				table.unique(["proxy_host_id", "bucket_start", "client_ip"]);
				table.index(["bucket_start"]);
				table.index(["proxy_host_id", "bucket_start"]);
			});
		})
		.then(() => {
			logger.info(`[${migrateName}] proxy_host_source_daily Table created`);

			return knex.schema.createTable("traffic_log_cursor", (table) => {
				table.increments().primary();
				// device + inode fingerprint, so renamed (rotated) files are recognized.
				table.string("file_key", 64).notNull();
				table.string("file_path").notNull();
				table.bigInteger("byte_offset").notNull().unsigned().defaultTo(0);
				table.dateTime("updated_on").notNull();
				table.unique(["file_key"]);
				table.index(["updated_on"]);
			});
		})
		.then(() => {
			logger.info(`[${migrateName}] traffic_log_cursor Table created`);
		});
};

/**
 * Undo Migrate
 *
 * @param   {import("knex").Knex}  knex
 * @returns {Promise}
 */
const down = (knex) => {
	logger.info(`[${migrateName}] Migrating Down...`);

	return knex.schema
		.dropTableIfExists("traffic_log_cursor")
		.then(() => knex.schema.dropTableIfExists("proxy_host_source_daily"))
		.then(() => knex.schema.dropTableIfExists("proxy_host_traffic_hourly"))
		.then(() => {
			logger.info(`[${migrateName}] traffic tables dropped`);
		});
};

export { up, down };
