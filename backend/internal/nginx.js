import fs from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import _ from "lodash";
import errs from "../lib/error.js";
import utils from "../lib/utils.js";
import { debug, nginx as logger } from "../logger.js";
import { ensureSecurityLogFile } from "../lib/security-log-file.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const internalNginx = {
	/**
	 * This will:
	 * - test the nginx config first to make sure it's OK
	 * - create / recreate the config for the host
	 * - test again
	 * - IF OK:  update the meta with online status
	 * - IF BAD: update the meta with offline status and remove the config entirely
	 * - then reload nginx
	 *
	 * @param   {Object|String}  model
	 * @param   {String}         host_type
	 * @param   {Object}         host
	 * @returns {Promise}
	 */
	configure: (model, host_type, host) => {
		let combined_meta = {};

		return internalNginx
			.test()
			.then(() => {
				// Nginx is OK
				// We're deleting this config regardless.
				// Don't throw errors, as the file may not exist at all
				// Delete the .err file too
				return internalNginx.deleteConfig(host_type, host, false, true);
			})
			.then(() => {
				return internalNginx.generateConfig(host_type, host);
			})
			.then(() => {
				// Test nginx again and update meta with result
				return internalNginx
					.test()
					.then(() => {
						// nginx is ok
						combined_meta = _.assign({}, host.meta, {
							nginx_online: true,
							nginx_err: null,
						});

						return model.query().where("id", host.id).patch({
							meta: combined_meta,
						});
					})
					.catch((err) => {
						// Remove the error_log line because it's a docker-ism false positive that doesn't need to be reported.
						// It will always look like this:
						//   nginx: [alert] could not open error log file: open() "/var/log/nginx/error.log" failed (6: No such device or address)

						const valid_lines = [];
						const err_lines = err.message.split("\n");
						err_lines.map((line) => {
							if (line.indexOf("/var/log/nginx/error.log") === -1) {
								valid_lines.push(line);
							}
							return true;
						});

						debug(logger, "Nginx test failed:", valid_lines.join("\n"));

						// config is bad, update meta and delete config
						combined_meta = _.assign({}, host.meta, {
							nginx_online: false,
							nginx_err: valid_lines.join("\n"),
						});

						return model
							.query()
							.where("id", host.id)
							.patch({
								meta: combined_meta,
							})
							.then(() => {
								internalNginx.renameConfigAsError(host_type, host);
							})
							.then(() => {
								return internalNginx.deleteConfig(host_type, host, true);
							});
					});
			})
			.then(() => {
				return internalNginx.reload();
			})
			.then(() => {
				return combined_meta;
			});
	},

	/**
	 * @returns {Promise}
	 */
	test: () => {
		debug(logger, "Testing Nginx configuration");
		return utils.execFile("/usr/sbin/nginx", ["-t", "-g", "error_log off;"]);
	},

	/**
	 * @returns {Promise}
	 */
	reload: () => {
		return internalNginx.test().then(() => {
			logger.info("Reloading Nginx");
			return utils.execFile("/usr/sbin/nginx", ["-s", "reload"]);
		});
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Integer} host_id
	 * @returns {String}
	 */
	getConfigName: (host_type, host_id) => {
		if (host_type === "default") {
			return "/data/nginx/default_host/site.conf";
		}
		return `/data/nginx/${internalNginx.getFileFriendlyHostType(host_type)}/${host_id}.conf`;
	},

	/**
	 * Generates custom locations
	 * @param   {Object}  host
	 * @returns {Promise}
	 */
	renderLocations: (host) => {
		return new Promise((resolve, reject) => {
			let template;

			try {
				template = fs.readFileSync(`${__dirname}/../templates/_location.conf`, { encoding: "utf8" });
			} catch (err) {
				reject(new errs.ConfigurationError(err.message));
				return;
			}

			const renderEngine = utils.getRenderEngine();
			let renderedLocations = "";

			const locationRendering = async () => {
				for (let i = 0; i < host.locations.length; i++) {
					const locationCopy = Object.assign(
						{},
						{ access_list_id: host.access_list_id },
						{ certificate_id: host.certificate_id },
						{ ssl_forced: host.ssl_forced },
						{ caching_enabled: host.caching_enabled },
						{ block_exploits: host.block_exploits },
						{ allow_websocket_upgrade: host.allow_websocket_upgrade },
						{ http2_support: host.http2_support },
						{ hsts_enabled: host.hsts_enabled },
						{ hsts_subdomains: host.hsts_subdomains },
						{ access_list: host.access_list },
						{ certificate: host.certificate },
						host.locations[i],
					);

					if (locationCopy.forward_host.indexOf("/") > -1) {
						const splitted = locationCopy.forward_host.split("/");

						locationCopy.forward_host = splitted.shift();
						locationCopy.forward_path = `/${splitted.join("/")}`;
					}

					renderedLocations += await renderEngine.parseAndRender(template, locationCopy);
				}
			};

			locationRendering().then(() => resolve(renderedLocations));
		});
	},

	/**
	 * Render a host configuration without changing the active configuration.
	 * This is used by startup upgrades so validation can happen before a working
	 * file is replaced.
	 *
	 * @param {String} host_type
	 * @param {Object} host_row
	 * @returns {Promise<string>}
	 */
	renderConfig: async (host_type, host_row) => {
		const host = JSON.parse(JSON.stringify(host_row));
		const niceHostType = internalNginx.getFileFriendlyHostType(host_type);
		let template;
		try {
			template = fs.readFileSync(`${__dirname}/../templates/${niceHostType}.conf`, { encoding: "utf8" });
		} catch (err) {
			throw new errs.ConfigurationError(err.message);
		}

		if (niceHostType !== "default") {
			host.use_default_location = true;
			if (host.advanced_config) {
				host.use_default_location = !internalNginx.advancedConfigHasDefaultLocation(host.advanced_config);
			}
		}
		if (niceHostType === "redirection_host" && ['http', 'https'].indexOf(host.forward_scheme.toLowerCase()) === -1) {
			host.forward_scheme = "$scheme";
		}
		if (host.locations) {
			const originalLocations = [].concat(host.locations);
			host.locations = await internalNginx.renderLocations(host);
			if (originalLocations.some((location) => location.path === "/")) {
				host.use_default_location = false;
			}
		}
		host.ipv6 = internalNginx.ipv6Enabled();
		return utils.getRenderEngine().parseAndRender(template, host);
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Object}  host
	 * @returns {Promise}
	 */
	generateConfig: async (host_type, host) => {
		const niceHostType = internalNginx.getFileFriendlyHostType(host_type);
		if (niceHostType === "proxy_host") {
			ensureSecurityLogFile(Number(host.id));
		}
		const filename = internalNginx.getConfigName(niceHostType, host.id);
		const configText = await internalNginx.renderConfig(host_type, host);
		fs.writeFileSync(filename, configText, { encoding: "utf8" });
		debug(logger, "Wrote config:", filename, configText);
		return true;
	},

	/**
	 * Replace older proxy-host config files only after all replacements have
	 * been rendered, security logs prepared, and Nginx accepts the candidate.
	 * On any failure every original file is restored before the caller continues.
	 *
	 * @param {Object[]} hosts
	 * @returns {Promise<boolean>} true when an upgrade was applied
	 */
	upgradeProxyHostConfigs: async (hosts) => {
		// Recover an interrupted prior upgrade before making new decisions. Without
		// a durable commit marker, a retained backup is authoritative: restore it
		// and retry the validated upgrade from the beginning.
		for (const host of hosts) {
			const filename = internalNginx.getConfigName("proxy_host", host.id);
			const backupFilename = `${filename}.security-backup`;
			const stagedFilename = `${filename}.security-upgrade`;
			if (fs.existsSync(backupFilename)) {
				if (fs.existsSync(filename)) fs.unlinkSync(filename);
				fs.renameSync(backupFilename, filename);
				logger.warn(`Recovered interrupted security upgrade for proxy host ${host.id}`);
			}
			fs.rmSync(stagedFilename, { force: true });
			ensureSecurityLogFile(Number(host.id));
		}

		const upgradeHosts = hosts.filter((host) => {
			const filename = internalNginx.getConfigName("proxy_host", host.id);
			try {
				return !fs.readFileSync(filename, "utf8").includes("_security.log security_json");
			} catch {
				return true;
			}
		});
		if (upgradeHosts.length === 0) {
			return false;
		}

		const staged = [];
		const backups = [];
		let committed = false;
		try {
			for (const host of upgradeHosts) {
				const filename = internalNginx.getConfigName("proxy_host", host.id);
				const stagedFilename = `${filename}.security-upgrade`;
				fs.writeFileSync(stagedFilename, await internalNginx.renderConfig("proxy_host", host), { encoding: "utf8", mode: 0o640 });
				staged.push({ filename, stagedFilename });
			}

			for (const item of staged) {
				const backupFilename = `${item.filename}.security-backup`;
				if (fs.existsSync(backupFilename)) {
					throw new Error(`Refusing to overwrite existing security upgrade backup: ${backupFilename}`);
				}
				const backup = { ...item, backupFilename, existed: fs.existsSync(item.filename) };
				if (backup.existed) {
					fs.renameSync(item.filename, backupFilename);
				}
				backups.push(backup);
				fs.renameSync(item.stagedFilename, item.filename);
			}
			await internalNginx.test();
			await internalNginx.reload();
			// A successful reload is the commit point. Backup cleanup failures must
			// never enter the destructive rollback path and remove active hosts.
			committed = true;
			for (const backup of backups) {
				if (backup.existed) {
					try {
						fs.unlinkSync(backup.backupFilename);
					} catch (cleanupErr) {
						logger.warn(`Could not remove committed proxy host backup ${backup.backupFilename}: ${cleanupErr.message}`);
					}
				}
			}
			logger.info(`Upgraded ${upgradeHosts.length} proxy host config(s) for security logging`);
			return true;
		} catch (err) {
			if (committed) {
				throw err;
			}
			for (const backup of backups.reverse()) {
				try {
					if (fs.existsSync(backup.filename)) {
						fs.unlinkSync(backup.filename);
					}
					if (backup.existed && fs.existsSync(backup.backupFilename)) {
						fs.renameSync(backup.backupFilename, backup.filename);
					}
				} catch (restoreErr) {
					logger.error(`Could not restore proxy host config ${backup.filename}: ${restoreErr.message}`);
				}
			}
			for (const item of staged) {
				fs.rmSync(item.stagedFilename, { force: true });
			}
			try {
				await internalNginx.test();
				await internalNginx.reload();
			} catch (restoreErr) {
				logger.error(`Restored Nginx configuration could not be reloaded: ${restoreErr.message}`);
			}
			throw err;
		}
	},

	/**
	 * This generates a temporary nginx config listening on port 80 for the domain names listed
	 * in the certificate setup. It allows the letsencrypt acme challenge to be requested by letsencrypt
	 * when requesting a certificate without having a hostname set up already.
	 *
	 * @param   {Object}  certificate
	 * @returns {Promise}
	 */
	generateLetsEncryptRequestConfig: (certificate) => {
		debug(logger, "Generating LetsEncrypt Request Config:", certificate);
		const renderEngine = utils.getRenderEngine();

		return new Promise((resolve, reject) => {
			let template = null;
			const filename = `/data/nginx/temp/letsencrypt_${certificate.id}.conf`;

			try {
				template = fs.readFileSync(`${__dirname}/../templates/letsencrypt-request.conf`, { encoding: "utf8" });
			} catch (err) {
				reject(new errs.ConfigurationError(err.message));
				return;
			}

			certificate.ipv6 = internalNginx.ipv6Enabled();

			renderEngine
				.parseAndRender(template, certificate)
				.then((config_text) => {
					fs.writeFileSync(filename, config_text, { encoding: "utf8" });
					debug(logger, "Wrote config:", filename, config_text);
					resolve(true);
				})
				.catch((err) => {
					debug(logger, `Could not write ${filename}:`, err.message);
					reject(new errs.ConfigurationError(err.message));
				});
		});
	},

	/**
	 * A simple wrapper around unlinkSync that writes to the logger
	 *
	 * @param   {String}  filename
	 */
	deleteFile: (filename) => {
		if (!fs.existsSync(filename)) {
			return;
		}
		try {
			debug(logger, `Deleting file: ${filename}`);
			fs.unlinkSync(filename);
		} catch (err) {
			debug(logger, "Could not delete file:", JSON.stringify(err, null, 2));
		}
	},

	/**
	 *
	 * @param   {String} host_type
	 * @returns String
	 */
	getFileFriendlyHostType: (host_type) => {
		return host_type.replace(/-/g, "_");
	},

	/**
	 * This removes the temporary nginx config file generated by `generateLetsEncryptRequestConfig`
	 *
	 * @param   {Object}  certificate
	 * @returns {Promise}
	 */
	deleteLetsEncryptRequestConfig: (certificate) => {
		const config_file = `/data/nginx/temp/letsencrypt_${certificate.id}.conf`;
		return new Promise((resolve /*, reject*/) => {
			internalNginx.deleteFile(config_file);
			resolve();
		});
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Object}  [host]
	 * @param   {Boolean} [delete_err_file]
	 * @returns {Promise}
	 */
	deleteConfig: (host_type, host, delete_err_file) => {
		const config_file = internalNginx.getConfigName(
			internalNginx.getFileFriendlyHostType(host_type),
			typeof host === "undefined" ? 0 : host.id,
		);
		const config_file_err = `${config_file}.err`;

		return new Promise((resolve /*, reject*/) => {
			internalNginx.deleteFile(config_file);
			if (delete_err_file) {
				internalNginx.deleteFile(config_file_err);
			}
			resolve();
		});
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Object}  [host]
	 * @returns {Promise}
	 */
	renameConfigAsError: (host_type, host) => {
		const config_file = internalNginx.getConfigName(
			internalNginx.getFileFriendlyHostType(host_type),
			typeof host === "undefined" ? 0 : host.id,
		);
		const config_file_err = `${config_file}.err`;

		return new Promise((resolve /*, reject*/) => {
			fs.unlink(config_file, () => {
				// ignore result, continue
				fs.rename(config_file, config_file_err, () => {
					// also ignore result, as this is a debugging informative file anyway
					resolve();
				});
			});
		});
	},

	/**
	 * @param   {String}  hostType
	 * @param   {Array}   hosts
	 * @returns {Promise}
	 */
	bulkGenerateConfigs: (hostType, hosts) => {
		const promises = [];
		hosts.map((host) => {
			promises.push(internalNginx.generateConfig(hostType, host));
			return true;
		});

		return Promise.all(promises);
	},

	/**
	 * @param   {String}  host_type
	 * @param   {Array}   hosts
	 * @returns {Promise}
	 */
	bulkDeleteConfigs: (host_type, hosts) => {
		const promises = [];
		hosts.map((host) => {
			promises.push(internalNginx.deleteConfig(host_type, host, true));
			return true;
		});

		return Promise.all(promises);
	},

	/**
	 * @param   {string}  config
	 * @returns {boolean}
	 */
	advancedConfigHasDefaultLocation: (cfg) => !!cfg.match(/^(?:.*;)?\s*?location\s*?\/\s*?{/im),

	/**
	 * @returns {boolean}
	 */
	ipv6Enabled: () => {
		if (typeof process.env.DISABLE_IPV6 !== "undefined") {
			const disabled = process.env.DISABLE_IPV6.toLowerCase();
			return !(disabled === "on" || disabled === "true" || disabled === "1" || disabled === "yes");
		}

		return true;
	},
};

export default internalNginx;
