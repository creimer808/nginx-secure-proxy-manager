import { IconAlertTriangle, IconCopy, IconRefresh, IconShieldSearch } from "@tabler/icons-react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
	type SecurityEvent,
	type SecurityEventFilters,
	type SecurityEventType,
	type SecurityLogKind,
	type SecurityLogTarget,
	type SecurityNginxUpgrade,
	type SecurityRange,
	type SecuritySeverity,
	updateSecuritySettings,
} from "src/api/backend";
import { HasPermission, Loading, LoadingPage } from "src/components";
import {
	useProxyHosts,
	useSecurityEvent,
	useSecurityEvents,
	useSecurityLogFiles,
	useSecurityLogs,
	useSecurityOverview,
	useSecuritySettings,
	useUser,
} from "src/hooks";
import { T, intl } from "src/locale";
import { PROXY_HOSTS, VIEW, isAdmin } from "src/modules/Permissions";
import styles from "./Security.module.css";

type Tab = "overview" | "events" | "logs" | "settings";
const ranges: SecurityRange[] = ["24h", "7d", "30d"];
const rangeMs: Record<SecurityRange, number> = { "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000 };
const tabs: { value: Tab; label: string }[] = [
	{ value: "overview", label: "security.overview" },
	{ value: "events", label: "security.events" },
	{ value: "logs", label: "security.raw-logs" },
	{ value: "settings", label: "security.configuration" },
];

const number = (value: number | null | undefined) => new Intl.NumberFormat().format(value ?? 0);
const date = (value: number | null | undefined) => (value ? new Date(value).toLocaleString() : "—");
const stringValue = (value: string | number | null | undefined) =>
	value === null || value === undefined || value === "" ? "—" : String(value);
const eventTypes: SecurityEventType[] = ["exploit_rule", "http_status", "nginx_error"];
const severities: SecuritySeverity[] = ["low", "medium", "high", "critical"];

function Security() {
	const [params, setParams] = useSearchParams();
	const openEvents = (filters: Record<string, string> = {}) =>
		setParams(() => {
			const next = new URLSearchParams({ tab: "events" });
			Object.entries(filters).forEach(([key, value]) => {
				if (value) next.set(key, value);
			});
			return next;
		});
	const selectedTab = params.get("tab");
	const tab: Tab = selectedTab && tabs.some((item) => item.value === selectedTab) ? (selectedTab as Tab) : "overview";
	const selectTab = (value: Tab) =>
		setParams((current) => {
			const next = new URLSearchParams(current);
			next.set("tab", value);
			return next;
		});
	useEffect(() => {
		let meta = document.querySelector<HTMLMetaElement>('meta[name="referrer"]');
		if (!meta) {
			meta = document.createElement("meta");
			meta.name = "referrer";
			document.head.append(meta);
		}
		const previous = meta.content;
		meta.content = "no-referrer";
		return () => {
			meta.content = previous;
		};
	}, []);
	return (
		<HasPermission section={PROXY_HOSTS} permission={VIEW} pageLoading loadingNoLogo>
			<main className={styles.page} aria-labelledby="security-heading">
				<h2 id="security-heading">
					<IconShieldSearch aria-hidden="true" /> <T id="security.title" />
				</h2>
				<p className="text-secondary">
					<T id="security.description" />
				</p>
				<nav className={styles.tabs} aria-label="Security sections">
					{tabs.map((item) => (
						<button
							type="button"
							key={item.value}
							className={`btn ${tab === item.value ? "btn-primary" : "btn-outline-primary"}`}
							aria-current={tab === item.value ? "page" : undefined}
							onClick={() => selectTab(item.value)}
						>
							<T id={item.label} />
						</button>
					))}
				</nav>
				{tab === "overview" && <Overview onEvents={openEvents} />}
				{tab === "events" && <Events params={params} setParams={setParams} />}
				{tab === "logs" && <RawLogs />}
				{tab === "settings" && <Settings />}
			</main>
		</HasPermission>
	);
}

function Overview({ onEvents }: { onEvents: (filters?: Record<string, string>) => void }) {
	const [range, setRange] = useState<SecurityRange>("24h");
	const { data, isLoading, isError, refetch } = useSecurityOverview(range);
	if (isLoading) return <LoadingPage noLogo />;
	if (isError || !data) return <ErrorState retry={() => refetch()} />;
	const go = (key?: string, value?: string) => () => {
		const to = Date.now();
		onEvents({ from: String(to - rangeMs[range]), to: String(to), ...(key && value ? { [key]: value } : {}) });
	};
	const stats: [string, number, string | undefined, string | undefined][] = [
		["security.total-events", data.totalEvents, undefined, undefined],
		["security.rule-matches", data.exploitRuleMatches, "eventType", "exploit_rule"],
		["security.nginx-errors", data.nginxErrors, "eventType", "nginx_error"],
		["security.status-401", data.statuses["401"], "status", "401"],
		["security.status-403", data.statuses["403"], "status", "403"],
		["security.status-404", data.statuses["404"], "status", "404"],
		["security.status-429", data.statuses["429"], "status", "429"],
		["security.status-5xx", data.statuses["5xx"], "statusClass", "5xx"],
	];
	return (
		<section aria-labelledby="security-overview-heading">
			<div className="d-flex justify-content-between align-items-center gap-2 flex-wrap">
				<h3 id="security-overview-heading" className="mb-0">
					<T id="security.overview" />
				</h3>
				{/* Tabler's .btn carries no margin of its own, and a JSX map emits no
				    whitespace text nodes, so these need .btn-group to sit together. */}
				<div className="btn-group" role="group" aria-label="Time range">
					{ranges.map((value) => (
						<button
							type="button"
							className={`btn btn-sm ${range === value ? "btn-primary" : "btn-outline-primary"}`}
							key={value}
							onClick={() => setRange(value)}
							aria-pressed={range === value}
						>
							<T id={`dashboard.range.${value}`} />
						</button>
					))}
				</div>
			</div>
			<div className={`${styles.stats} mt-3`}>
				{stats.map(([label, value, key, filter]) => (
					<button type="button" className="card card-sm text-start" key={label} onClick={go(key, filter)}>
						<div className="card-body">
							<div className="subheader">
								<T id={label} />
							</div>
							<strong className="h2">{number(value)}</strong>
						</div>
					</button>
				))}
			</div>
			<Collector health={data.collector} />
			<div className="row row-cards mt-3">
				<Top
					title="security.top-rules"
					values={data.topRules}
					field="ruleId"
					onEvents={onEvents}
					range={range}
				/>
				<Top
					title="security.top-sources"
					values={data.topSources}
					field="clientIp"
					onEvents={onEvents}
					range={range}
				/>
				<Top
					title="security.top-hosts"
					values={data.topHosts}
					field="proxyHostId"
					onEvents={onEvents}
					range={range}
				/>
				<Top
					title="security.top-statuses"
					values={data.topStatuses}
					field="status"
					onEvents={onEvents}
					range={range}
				/>
				<Top
					title="security.top-methods"
					values={data.topMethods}
					field="method"
					onEvents={onEvents}
					range={range}
				/>
			</div>
			<div className="card mt-3">
				<div className="card-header">
					<h3 className="card-title">
						<T id="security.timeline" />
					</h3>
				</div>
				{data.timeline.length ? (
					<div className="table-responsive">
						<table className="table table-sm table-vcenter card-table">
							<thead>
								<tr>
									<th scope="col">
										<T id="security.time" />
									</th>
									<th scope="col">
										<T id="security.type" />
									</th>
									<th scope="col">
										<T id="security.severity" />
									</th>
									<th scope="col" className="text-end">
										<T id="security.count" />
									</th>
								</tr>
							</thead>
							<tbody>
								{data.timeline.map((point) => (
									<tr key={`${point.bucketStart}-${point.eventType}-${point.severity}`}>
										<td>{date(point.bucketStart)}</td>
										<td>{point.eventType}</td>
										<td>{point.severity}</td>
										<td className="text-end">{number(point.count)}</td>
									</tr>
								))}
							</tbody>
						</table>
					</div>
				) : (
					<div className="card-body">
						<p className="text-secondary mb-0">
							<T id="security.empty" />
						</p>
					</div>
				)}
			</div>
		</section>
	);
}

function Collector({
	health,
}: {
	health: {
		enabled?: boolean;
		available?: boolean;
		lagMs?: number | null;
		filesPending?: number;
		malformedLines?: number;
		limitReached?: boolean;
		databaseHighWaterReached?: boolean;
		rawLogDiskHighWaterReached?: boolean;
		lastErrorSummary?: string | null;
	};
}) {
	const warning =
		health.databaseHighWaterReached ||
		health.rawLogDiskHighWaterReached ||
		health.limitReached ||
		health.lastErrorSummary;
	return (
		<aside className={`alert ${warning ? "alert-warning" : "alert-info"} mt-3`} aria-live="polite">
			<strong>
				<T id="security.collector-health" />:
			</strong>{" "}
			{health.enabled === false ? (
				<T id="security.collector-disabled" />
			) : health.available === false ? (
				<T id="security.collector-unavailable" />
			) : (
				<>
					<T id="security.collector-available" />
					{health.lagMs !== undefined && health.lagMs !== null
						? ` — ${Math.round(health.lagMs / 1000)}s lag`
						: ""}
					{health.filesPending ? ` — ${health.filesPending} pending` : ""}
					{health.limitReached ? " — limit reached" : ""}
					{health.databaseHighWaterReached ? " — database high-water reached" : ""}
					{health.rawLogDiskHighWaterReached ? " — raw-log disk high-water reached" : ""}
					{health.lastErrorSummary ? ` — ${health.lastErrorSummary}` : ""}
				</>
			)}
		</aside>
	);
}

function Top({
	title,
	values,
	field,
	onEvents,
	range,
}: {
	title: string;
	values: {
		count: number;
		ruleId?: string;
		clientIp?: string;
		proxyHostId?: number;
		status?: number;
		method?: string;
	}[];
	field: "ruleId" | "clientIp" | "proxyHostId" | "status" | "method";
	onEvents: (filters?: Record<string, string>) => void;
	range: SecurityRange;
}) {
	return (
		<section className="col-lg-4 col-md-6">
			<div className="card h-100">
				<div className="card-body">
					<h3 className="h4">
						<T id={title} />
					</h3>
					{values.length ? (
						<ol className="mb-0">
							{values.map((value, index) => {
								const content = value[field];
								return (
									<li key={`${String(content)}-${index}`}>
										<button
											type="button"
											className={styles.tableButton}
											onClick={() => {
												const to = Date.now();
												onEvents({
													from: String(to - rangeMs[range]),
													to: String(to),
													[field]: String(content),
												});
											}}
										>
											{stringValue(content)}{" "}
											<span className="text-secondary">({number(value.count)})</span>
										</button>
									</li>
								);
							})}
						</ol>
					) : (
						<p className="text-secondary mb-0">
							<T id="security.empty" />
						</p>
					)}
				</div>
			</div>
		</section>
	);
}

function Events({
	params,
	setParams,
}: {
	params: URLSearchParams;
	setParams: (next: URLSearchParams | ((current: URLSearchParams) => URLSearchParams)) => void;
}) {
	const { data: hosts = [] } = useProxyHosts();
	const [text, setText] = useState("");
	const [previousCursors, setPreviousCursors] = useState<string[]>([]);
	const filters = useMemo<SecurityEventFilters>(
		() => ({
			from: params.get("from") || undefined,
			to: params.get("to") || undefined,
			proxyHostId: toNumber(params.get("proxyHostId")),
			eventType: (params.get("eventType") as SecurityEventType) || undefined,
			severity: (params.get("severity") as SecuritySeverity) || undefined,
			ruleId: params.get("ruleId") || undefined,
			clientIp: params.get("clientIp") || undefined,
			status: toNumber(params.get("status")),
			statusClass: params.get("statusClass") === "5xx" ? "5xx" : undefined,
			method: params.get("method") || undefined,
			query: text || undefined,
			cursor: params.get("cursor") || undefined,
		}),
		[params, text],
	);
	const { data, isLoading, isError, refetch, isFetching } = useSecurityEvents(filters);
	const update = (name: string, value: string) => {
		setPreviousCursors([]);
		setParams((current) => {
			const next = new URLSearchParams(current);
			next.delete("cursor");
			if (value) next.set(name, value);
			else next.delete(name);
			return next;
		});
	};
	return (
		<section aria-labelledby="security-events-heading">
			<h3 id="security-events-heading">
				<T id="security.events" />
			</h3>
			<p className="text-secondary">
				<T id="security.query-warning" />
			</p>
			<div className={styles.filters}>
				<Select
					label="security.host"
					value={params.get("proxyHostId") || ""}
					onChange={(value) => update("proxyHostId", value)}
					options={hosts.map((host) => [String(host.id), host.domainNames.join(", ") || `#${host.id}`])}
				/>
				<Select
					label="security.type"
					value={params.get("eventType") || ""}
					onChange={(value) => update("eventType", value)}
					options={eventTypes.map((value) => [value, value])}
				/>
				<Select
					label="security.severity"
					value={params.get("severity") || ""}
					onChange={(value) => update("severity", value)}
					options={severities.map((value) => [value, value])}
				/>
				<Input
					label="security.source-ip"
					value={params.get("clientIp") || ""}
					onChange={(value) => update("clientIp", value)}
				/>
				<Input
					label="security.rule"
					value={params.get("ruleId") || ""}
					onChange={(value) => update("ruleId", value)}
				/>
				<Input
					label="security.from"
					value={params.get("from") || ""}
					onChange={(value) => update("from", value)}
				/>
				<Input label="security.to" value={params.get("to") || ""} onChange={(value) => update("to", value)} />
				<Input
					label="security.status"
					inputMode="numeric"
					value={params.get("status") || ""}
					onChange={(value) => update("status", value)}
				/>
				<Input
					label="security.method"
					value={params.get("method") || ""}
					onChange={(value) => update("method", value.toUpperCase())}
				/>
				<Input
					label="security.metadata-search"
					value={text}
					onChange={(value) => {
						setText(value);
						update("cursor", "");
					}}
				/>
			</div>
			{isLoading ? (
				<Loading noLogo />
			) : isError ? (
				<ErrorState retry={() => refetch()} />
			) : (
				<EventTable events={data?.items ?? []} isFetching={isFetching} />
			)}
			<div className="d-flex gap-2 mt-3">
				{previousCursors.length > 0 && (
					<button
						type="button"
						className="btn btn-outline-primary"
						onClick={() => {
							const previous = previousCursors[previousCursors.length - 1];
							setPreviousCursors((items) => items.slice(0, -1));
							setParams((current) => {
								const next = new URLSearchParams(current);
								if (previous) next.set("cursor", previous);
								else next.delete("cursor");
								return next;
							});
						}}
					>
						<T id="security.previous-page" />
					</button>
				)}
				{data?.nextCursor && (
					<button
						type="button"
						className="btn btn-primary"
						onClick={() => {
							setPreviousCursors((items) => [...items, params.get("cursor") || ""]);
							setParams((current) => {
								const next = new URLSearchParams(current);
								next.set("cursor", data.nextCursor as string);
								return next;
							});
						}}
					>
						<T id="security.next-page" />
					</button>
				)}
			</div>
		</section>
	);
}

function EventTable({ events, isFetching }: { events: SecurityEvent[]; isFetching: boolean }) {
	const [selected, setSelected] = useState<SecurityEvent | null>(null);
	return (
		<>
			<div className="table-responsive">
				<table className="table table-sm table-vcenter">
					<thead>
						<tr>
							{[
								"security.time",
								"security.type",
								"security.severity",
								"security.rule",
								"security.source-ip",
								"security.host",
								"security.method",
								"security.uri",
								"security.status",
								"security.duration",
							].map((heading) => (
								<th scope="col" key={heading}>
									<T id={heading} />
								</th>
							))}
						</tr>
					</thead>
					<tbody>
						{events.map((event) => (
							<tr key={event.id}>
								<td>{date(event.occurredAtMs)}</td>
								<td>{event.eventType}</td>
								<td>{event.severity}</td>
								<td>{stringValue(event.ruleId)}</td>
								<td>{stringValue(event.clientIp)}</td>
								<td>{stringValue(event.hostDomainSnapshot)}</td>
								<td>{stringValue(event.method)}</td>
								<td>
									<button
										type="button"
										className={styles.tableButton}
										onClick={() => setSelected(event)}
										aria-label={`View details for ${event.requestUri || event.id}`}
									>
										{stringValue(event.requestUri)}
									</button>
								</td>
								<td>{stringValue(event.status)}</td>
								<td>{event.requestTimeMs === null ? "—" : `${event.requestTimeMs}ms`}</td>
							</tr>
						))}
						{!events.length && (
							<tr>
								<td colSpan={10} className="text-center text-secondary">
									<T id="security.empty" />
								</td>
							</tr>
						)}
					</tbody>
				</table>
			</div>
			{isFetching && (
				<span role="status">
					<T id="dashboard.metrics.updating" />
				</span>
			)}
			{selected && <EventDetails event={selected} onClose={() => setSelected(null)} />}
		</>
	);
}

function EventDetails({ event, onClose }: { event: SecurityEvent; onClose: () => void }) {
	const detail = useSecurityEvent(event.eventId);
	const closeRef = useRef<HTMLButtonElement>(null);
	const openerRef = useRef(document.activeElement as HTMLElement | null);
	useEffect(() => {
		closeRef.current?.focus();
		const keydown = (key: KeyboardEvent) => {
			if (key.key === "Escape") onClose();
		};
		window.addEventListener("keydown", keydown);
		return () => {
			window.removeEventListener("keydown", keydown);
			openerRef.current?.focus();
		};
	}, [onClose]);
	const record = detail.data || event;
	const fields: [string, string | number | null | undefined][] = [
		["security.time", record.occurredAtMs],
		["security.ingested-at", record.createdOn],
		["security.event-id", record.eventId],
		["security.request-id", record.requestId],
		["security.schema-version", record.schemaVersion],
		["security.ruleset-version", record.rulesetVersion],
		["security.type", record.eventType],
		["security.severity", record.severity],
		["security.rule", record.ruleId],
		["security.rule-category", record.ruleCategory],
		["security.rule-action", record.ruleAction],
		["security.source-ip", record.clientIp],
		["security.peer-ip", record.peerIp],
		["security.peer-port", record.peerPort],
		["security.host", record.requestHost || record.hostDomainSnapshot],
		["security.method", record.method],
		["security.scheme", record.scheme],
		["security.protocol", record.httpProtocol],
		["security.uri", record.requestUri],
		["security.status", record.status],
		["security.upstream-status", record.upstreamStatus],
		["security.request-bytes", record.requestBytes],
		["security.response-bytes", record.responseBytes],
		["security.duration", record.requestTimeMs],
		["security.upstream-address", record.upstreamAddr],
		["security.upstream-duration", record.upstreamTimeMs],
		["security.tls-protocol", record.tlsProtocol],
		["security.tls-cipher", record.tlsCipher],
		["security.remote-user", record.remoteUser],
		["security.user-agent", record.userAgent],
		["security.referrer", record.referrer],
		["security.nginx-level", record.nginxErrorLevel],
		["security.nginx-message", record.nginxErrorMessage],
	];
	return (
		<section className={styles.detail} role="dialog" aria-modal="true" aria-labelledby="security-event-details">
			<div className="d-flex justify-content-between">
				<h3 id="security-event-details">
					<T id="security.event-details" />
				</h3>
				<button ref={closeRef} type="button" className="btn btn-outline-secondary btn-sm" onClick={onClose}>
					<T id="action.close" />
				</button>
			</div>
			{detail.isLoading ? (
				<Loading noLogo />
			) : detail.isError ? (
				<p className="alert alert-warning">
					<T id="security.detail-unavailable" />
				</p>
			) : (
				<div className={styles.detailGrid}>
					{fields.map(([label, value]) => (
						<div key={label}>
							<strong>
								<T id={label} />
							</strong>
							<div className={styles.value}>
								{label === "security.time" ? date(value as number) : stringValue(value)}
							</div>
						</div>
					))}
				</div>
			)}
		</section>
	);
}

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
		<section aria-labelledby="security-logs-heading">
			<h3 id="security-logs-heading">
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
					<T id="security.hosts-upgraded" />: {number(upgrade.hostsUpgraded)} / {number(upgrade.hostsTotal)}
				</li>
				{upgrade.hostsSkipped > 0 && (
					<li>
						<T id="security.hosts-skipped" />: {number(upgrade.hostsSkipped)}
					</li>
				)}
				{upgrade.hostsPending > 0 && (
					<li>
						<T id="security.hosts-pending" />: {number(upgrade.hostsPending)}
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

function Settings() {
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

function Input({
	label,
	value,
	onChange,
	inputMode,
}: {
	label: string;
	value: string;
	onChange: (value: string) => void;
	inputMode?: "numeric";
}) {
	const id = `security-${label}`;
	return (
		<div>
			<label htmlFor={id} className="form-label">
				{intl.formatMessage({ id: label })}
			</label>
			<input
				id={id}
				className="form-control"
				value={value}
				inputMode={inputMode}
				onChange={(event) => onChange(event.target.value)}
			/>
		</div>
	);
}
function Select({
	label,
	value,
	onChange,
	options,
	disabled,
}: {
	label: string;
	value: string;
	onChange: (value: string) => void;
	options: [string, string][];
	disabled?: boolean;
}) {
	const id = `security-${label}`;
	return (
		<div>
			<label htmlFor={id} className="form-label">
				{intl.formatMessage({ id: label })}
			</label>
			<select
				id={id}
				className="form-select"
				value={value}
				disabled={disabled}
				onChange={(event) => onChange(event.target.value)}
			>
				<option value="">{intl.formatMessage({ id: "security.all" })}</option>
				{options.map(([key, text]) => (
					<option value={key} key={key}>
						{text}
					</option>
				))}
			</select>
		</div>
	);
}
function ErrorState({ retry }: { retry: () => void }) {
	return (
		<div className="alert alert-danger" role="alert">
			<T id="security.error" />{" "}
			<button type="button" className="btn btn-sm btn-outline-danger" onClick={retry}>
				<IconRefresh aria-hidden="true" /> <T id="dashboard.metrics.error-retry" />
			</button>
		</div>
	);
}
function toNumber(value: string | null): number | undefined {
	return value && /^\d+$/.test(value) ? Number(value) : undefined;
}
export default Security;
