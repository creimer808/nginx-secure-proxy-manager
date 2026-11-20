import { IconAlertTriangle } from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { type SecurityNginxUpgrade, updateSecuritySettings } from "src/api/backend";
import { useSecuritySettings, useUser } from "src/hooks";
import { T } from "src/locale";
import { isAdmin } from "src/modules/Permissions";
import { formatNumber } from "src/modules/Format";

/**
 * Whether Nginx actually received the security logging directive is invisible
 * from the event tables when the answer is "no events at all". The startup
 * upgrade records its outcome so this panel can say so directly.
 */
function NginxUpgrade({ upgrade }: { upgrade: SecurityNginxUpgrade | null | undefined }) {
	if (upgrade === undefined) return null;
	if (upgrade === null) {
		return (
			<div className="alert alert-info" role="status">
				<T id="security.nginx-upgrade-unknown" />
			</div>
		);
	}
	const incomplete = upgrade.hostsSkipped > 0 || upgrade.hostsPending > 0 || Boolean(upgrade.lastErrorSummary);
	return (
		<div className={`alert ${incomplete ? "alert-warning" : "alert-success"}`} role="status">
			<h4 className="alert-title">
				<T id="security.nginx-upgrade" />
			</h4>
			<p className="mb-1">
				<T id={incomplete ? "security.nginx-upgrade-incomplete" : "security.nginx-upgrade-active"} />
			</p>
			<ul className="mb-0">
				<li>
					<T id="security.hosts-upgraded" />: {formatNumber(upgrade.hostsUpgraded)} /{" "}
					{formatNumber(upgrade.hostsTotal)}
				</li>
				{upgrade.hostsSkipped > 0 && (
					<li>
						<T id="security.hosts-skipped" />: {formatNumber(upgrade.hostsSkipped)}
					</li>
				)}
				{upgrade.hostsPending > 0 && (
					<li>
						<T id="security.hosts-pending" />: {formatNumber(upgrade.hostsPending)}
					</li>
				)}
				{upgrade.reloadDeferred && (
					<li>
						<T id="security.reload-deferred" />
					</li>
				)}
				{upgrade.lastErrorSummary && <li>{upgrade.lastErrorSummary}</li>}
			</ul>
		</div>
	);
}

function Configuration() {
	const { data: user } = useUser("me");
	const admin = isAdmin(user?.roles);
	const settings = useSecuritySettings(admin);
	const [value, setValue] = useState("");
	const client = useQueryClient();
	const mutation = useMutation({
		mutationFn: (retentionDays: number) => updateSecuritySettings(retentionDays),
		onSuccess: () => client.invalidateQueries({ queryKey: ["security", "settings"] }),
	});
	useEffect(() => {
		if (settings.data) setValue(String(settings.data.retentionDays));
	}, [settings.data]);
	if (!admin)
		return (
			<section>
				<h3>
					<T id="security.configuration" />
				</h3>
				<div className="alert alert-info">
					<T id="security.admin-only" />
				</div>
			</section>
		);
	const save = () => {
		const days = Number(value);
		if (!Number.isInteger(days) || days < 7 || days > 365) return;
		if (
			settings.data &&
			days < settings.data.retentionDays &&
			!window.confirm("Lowering retention deletes detailed events during the next cleanup cycle. Continue?")
		)
			return;
		mutation.mutate(days);
	};
	return (
		<section aria-labelledby="security-settings-heading">
			<h3 id="security-settings-heading">
				<T id="security.configuration" />
			</h3>
			<NginxUpgrade upgrade={settings.data?.nginxUpgrade} />
			<div className="alert alert-warning">
				<IconAlertTriangle aria-hidden="true" /> <T id="security.retention-warning" />
			</div>
			<div className="mb-3">
				<label htmlFor="retention-days" className="form-label">
					<T id="security.retention-days" />
				</label>
				<div className="input-group">
					<input
						id="retention-days"
						type="number"
						className="form-control"
						min="7"
						max="365"
						value={value}
						onChange={(event) => setValue(event.target.value)}
					/>
					<button type="button" className="btn btn-primary" disabled={mutation.isPending} onClick={save}>
						<T id="save" />
					</button>
				</div>
			</div>
			{mutation.isError && (
				<p className="text-danger" role="alert">
					{mutation.error.message}
				</p>
			)}
			{mutation.isSuccess && (
				<p className="text-success" role="status">
					<T id="security.saved" />
				</p>
			)}
			<p className="text-secondary mt-3">
				<T id="security.retention-detail" />
			</p>
		</section>
	);
}

export default Configuration;
