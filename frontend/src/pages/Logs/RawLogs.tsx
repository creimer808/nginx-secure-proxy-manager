import { IconCopy } from "@tabler/icons-react";
import { useEffect, useState } from "react";
import type { SecurityLogKind, SecurityLogTarget } from "src/api/backend";
import { Loading } from "src/components";
import { useProxyHosts, useSecurityLogFiles, useSecurityLogs, useUser } from "src/hooks";
import { intl, T } from "src/locale";
import { isAdmin } from "src/modules/Permissions";
import { Input, Select } from "./EventFilters";
import styles from "./Logs.module.css";

const toNumber = (value: string): number | undefined => (/^\d+$/.test(value) ? Number(value) : undefined);

function RawLogs() {
	const { data: user } = useUser("me");
	const admin = isAdmin(user?.roles);
	const { data: hosts = [] } = useProxyHosts();
	const [target, setTarget] = useState<SecurityLogTarget>("host");
	const [hostId, setHostId] = useState<number | undefined>();
	const [kind, setKind] = useState<SecurityLogKind>("security");
	const [rotation, setRotation] = useState("current");
	const [query, setQuery] = useState("");
	const [cursor, setCursor] = useState<string | undefined>();
	const [direction, setDirection] = useState<"forward" | "backward">("backward");
	const inventory = useSecurityLogFiles(target, kind, hostId);
	const files = inventory.data || [];
	const canRead = target === "global" || Boolean(hostId);
	const hasRotation = files.some((file) => file.rotation === rotation);
	const logs = useSecurityLogs(
		{ target, kind, proxyHostId: hostId, rotation, cursor, direction, query: query || undefined },
		canRead && hasRotation,
	);
	const [copyMessage, setCopyMessage] = useState("");
	// biome-ignore lint/correctness/useExhaustiveDependencies: reset navigation when the selected source changes.
	useEffect(() => {
		setRotation("current");
		setCursor(undefined);
	}, [target, hostId, kind]);
	const copy = async (line: string) => {
		try {
			if (!navigator.clipboard) throw new Error();
			await navigator.clipboard.writeText(line);
			setCopyMessage(intl.formatMessage({ id: "security.copied" }));
		} catch {
			setCopyMessage(intl.formatMessage({ id: "security.copy-failed" }));
		}
	};
	return (
		<section aria-labelledby="logs-raw-heading">
			<h3 id="logs-raw-heading">
				<T id="security.raw-logs" />
			</h3>
			<p className="text-secondary">
				<T id="security.raw-log-notice" />
			</p>
			<div className={styles.filters}>
				<Select
					label="security.log-target"
					value={target}
					onChange={(value) => setTarget(value as SecurityLogTarget)}
					options={[
						["host", "Proxy host"],
						...(admin ? ([["global", "Global fallback"]] as [string, string][]) : []),
					]}
				/>
				<Select
					label="security.host"
					value={hostId ? String(hostId) : ""}
					onChange={(value) => setHostId(toNumber(value))}
					options={hosts.map((host) => [String(host.id), host.domainNames.join(", ") || `#${host.id}`])}
					disabled={target === "global"}
				/>
				<Select
					label="security.log-kind"
					value={kind}
					onChange={(value) => setKind(value as SecurityLogKind)}
					options={(["access", "error", "security"] as SecurityLogKind[]).map((value) => [value, value])}
				/>
				<Select
					label="security.rotation"
					value={rotation}
					onChange={setRotation}
					options={files.map((file) => [file.rotation, file.rotation])}
				/>
				<Input
					label="security.search-logs"
					value={query}
					onChange={(value) => {
						setQuery(value);
						setCursor(undefined);
					}}
				/>
			</div>
			{inventory.isLoading ? (
				<Loading noLogo />
			) : inventory.isError ? (
				<div className="alert alert-warning">
					<T id="security.log-inventory-error" />
				</div>
			) : !canRead ? (
				<div className="alert alert-info">
					<T id="security.select-host" />
				</div>
			) : !files.length ? (
				<div className="alert alert-info">
					<T id="security.empty" />
				</div>
			) : logs.isLoading ? (
				<Loading noLogo />
			) : logs.isError ? (
				<div className="alert alert-warning">
					<T id="security.log-error" /> {logs.error.message}
				</div>
			) : (
				<>
					{logs.data?.partial && (
						<div className="alert alert-info">
							<T id="security.partial-results" />
						</div>
					)}
					<p className="visually-hidden" role="status">
						{copyMessage}
					</p>
					<div className="card">
						<div className="card-body">
							{logs.data?.lines.length ? (
								logs.data.lines.map((item) => (
									<div className={styles.rawLine} key={item.offset}>
										<button
											type="button"
											className="btn btn-sm btn-ghost-secondary"
											aria-label="Copy log line"
											onClick={() => copy(item.line)}
										>
											<IconCopy aria-hidden="true" />
										</button>
										<code>{item.line}</code>
									</div>
								))
							) : (
								<p className="text-secondary mb-0">
									<T id="security.empty" />
								</p>
							)}
						</div>
					</div>
					<div className="d-flex gap-2 mt-3">
						<button
							type="button"
							className="btn btn-outline-primary"
							disabled={!logs.data?.previousCursor}
							onClick={() => {
								setDirection("backward");
								setCursor(logs.data?.previousCursor || undefined);
							}}
						>
							<T id="security.previous-page" />
						</button>
						<button
							type="button"
							className="btn btn-primary"
							disabled={!logs.data?.nextCursor}
							onClick={() => {
								setDirection("forward");
								setCursor(logs.data?.nextCursor || undefined);
							}}
						>
							<T id="security.next-page" />
						</button>
					</div>
				</>
			)}
		</section>
	);
}

export default RawLogs;
