import { mergeAndBoundSources, retentionCutoff } from "./traffic-aggregate.js";

/**
 * Transaction body for persisting traffic aggregates.
 *
 * Extracted from the collector so it can be unit-tested with a real transaction
 * handle, independent of the application database/config bootstrap. Cursors are
 * advanced inside the same transaction as the metric writes, so a failure rolls
 * back the cursor too and the data is reread safely on the next cycle.
 *
 * @param {import("knex").Knex.Transaction} trx
 * @param {{hourly:Map<string,Object>, sources:Map<string,Map<string,Object>>, cursors:Array<{fileKey:string,filePath:string,newByteOffset:number}>}} data
 * @param {{runRetention?:boolean, nowEpoch?:number, retentionDays?:number, cursorGraceDays?:number, sourceMax?:number}} [options]
 */
const writeAggregates = async (trx, { hourly, sources, cursors }, options = {}) => {
	const {
		runRetention = false,
		nowEpoch = Math.floor(Date.now() / 1000),
		retentionDays = 30,
		cursorGraceDays = 30,
		sourceMax = 10,
	} = options;

	// Hourly traffic: portable read-modify-write upsert.
	for (const entry of hourly.values()) {
		const existing = await trx("proxy_host_traffic_hourly")
			.where("proxy_host_id", entry.proxy_host_id)
			.andWhere("bucket_start", entry.bucket_start)
			.first();

		if (existing) {
			await trx("proxy_host_traffic_hourly").where("id", existing.id).update({
				request_count: Number(existing.request_count) + entry.request_count,
				status_1xx: Number(existing.status_1xx) + entry.status_1xx,
				status_2xx: Number(existing.status_2xx) + entry.status_2xx,
				status_3xx: Number(existing.status_3xx) + entry.status_3xx,
				status_4xx: Number(existing.status_4xx) + entry.status_4xx,
				status_5xx: Number(existing.status_5xx) + entry.status_5xx,
				bytes_sent: Number(existing.bytes_sent) + entry.bytes_sent,
			});
		} else {
			await trx("proxy_host_traffic_hourly").insert(entry);
		}
	}

	// Daily sources: merge with stored top-N, replace the bounded partition.
	for (const [dayKey, candMap] of sources) {
		const [hostIdStr, dayStr] = dayKey.split(":");
		const proxyHostId = Number(hostIdStr);
		const bucketStart = Number(dayStr);

		const existingRows = await trx("proxy_host_source_daily")
			.where("proxy_host_id", proxyHostId)
			.andWhere("bucket_start", bucketStart);

		const bounded = mergeAndBoundSources(existingRows, candMap, sourceMax);

		if (existingRows.length) {
			await trx("proxy_host_source_daily")
				.where("proxy_host_id", proxyHostId)
				.andWhere("bucket_start", bucketStart)
				.del();
		}

		for (const row of bounded) {
			await trx("proxy_host_source_daily").insert({
				proxy_host_id: proxyHostId,
				bucket_start: bucketStart,
				client_ip: row.client_ip,
				status_4xx: row.status_4xx,
				status_5xx: row.status_5xx,
				observed_count: row.observed_count,
			});
		}
	}

	// Cursors advance only inside this transaction.
	for (const cursor of cursors) {
		const existing = await trx("traffic_log_cursor").where("file_key", cursor.fileKey).first();
		if (existing) {
			await trx("traffic_log_cursor").where("id", existing.id).update({
				file_path: cursor.filePath,
				byte_offset: cursor.newByteOffset,
				updated_on: new Date(),
			});
		} else {
			await trx("traffic_log_cursor").insert({
				file_key: cursor.fileKey,
				file_path: cursor.filePath,
				byte_offset: cursor.newByteOffset,
				updated_on: new Date(),
			});
		}
	}

	// Retention: bounded, indexed deletes.
	if (runRetention) {
		const cutoff = retentionCutoff(nowEpoch, retentionDays);
		await trx("proxy_host_traffic_hourly").where("bucket_start", "<", cutoff).del();
		await trx("proxy_host_source_daily").where("bucket_start", "<", cutoff).del();
		const cursorCutoff = new Date((nowEpoch - cursorGraceDays * 86400) * 1000);
		await trx("traffic_log_cursor").where("updated_on", "<", cursorCutoff).del();
	}
};

export { writeAggregates };
