import { IconActivity, IconAlertTriangle, IconDatabaseExport, IconServerOff } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import type { DashboardRange, DashboardReport, DashboardSeriesPoint } from "src/api/backend";
import { Button, Loading } from "src/components";
import { useDashboardReport } from "src/hooks";
import { getLocale, T } from "src/locale";
import styles from "./Dashboard.module.css";

const RANGES: DashboardRange[] = ["24h", "7d", "30d"];

const formatNumber = (value: number): string => {
	try {
		return new Intl.NumberFormat(getLocale()).format(value);
	} catch {
		return String(value);
	}
};

const formatBytes = (bytes: number): string => {
	if (!bytes) {
		return "0 B";
	}
	const units = ["B", "KB", "MB", "GB", "TB"];
	const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
	const value = bytes / 1024 ** i;
	try {
		return `${new Intl.NumberFormat(getLocale(), { maximumFractionDigits: 1 }).format(value)} ${units[i]}`;
	} catch {
		return `${value} ${units[i]}`;
	}
};

const formatBucketLabel = (bucketStart: number, range: DashboardRange): string => {
	try {
		return new Intl.DateTimeFormat(
			getLocale(),
			range === "24h" ? { hour: "numeric" } : { month: "short", day: "numeric", timeZone: "UTC" },
		).format(new Date(bucketStart * 1000));
	} catch {
		return String(bucketStart);
	}
};

const maxSeriesRequests = (series: DashboardSeriesPoint[]): number =>
	series.reduce((max, point) => Math.max(max, point.requestCount), 0);

const RANGE_BUCKETS: Record<DashboardRange, { count: number; seconds: number }> = {
	"24h": { count: 24, seconds: 60 * 60 },
	// Rolling day ranges include partial UTC days at both boundaries.
	"7d": { count: 8, seconds: 24 * 60 * 60 },
	"30d": { count: 31, seconds: 24 * 60 * 60 },
};

const fillSeriesGaps = (
	series: DashboardSeriesPoint[],
	range: DashboardRange,
	generatedAt: number,
): DashboardSeriesPoint[] => {
	if (series.length === 0) {
		return [];
	}

	const { count, seconds } = RANGE_BUCKETS[range];
	const end = Math.floor(generatedAt / seconds) * seconds;
	const start = end - (count - 1) * seconds;
	const pointsByBucket = new Map(series.map((point) => [point.bucketStart, point]));

	return Array.from({ length: count }, (_, index) => {
		const bucketStart = start + index * seconds;
		return (
			pointsByBucket.get(bucketStart) ?? {
				bucketStart,
				requestCount: 0,
				status1xx: 0,
				status2xx: 0,
				status3xx: 0,
				status4xx: 0,
				status5xx: 0,
			}
		);
	});
};

const SecurityTrafficDashboard = () => {
	const [range, setRange] = useState<DashboardRange>("24h");
	const { data, isLoading, isError, isFetching, refetch } = useDashboardReport(range);

	const disabled = data && data.collection.enabled === false;
	const noVisibleHosts = !!data && data.posture.enabled + data.posture.disabled === 0;
	const noTraffic = !!data && !noVisibleHosts && data.traffic.requests === 0 && data.series.length === 0;

	return (
		<section className={styles.dashboard} aria-labelledby="security-traffic-heading">
			<div className={styles.dashboardHeader}>
				<div>
					<h3 id="security-traffic-heading" className="mb-0">
						<T id="dashboard.metrics.title" />
					</h3>
					<a href="/security" className="small"><T id="dashboard.metrics.open-security" /></a>
				</div>
				<div className={styles.headerActions}>
					{isFetching && !isLoading && (
						<span className={styles.updating} role="status">
							<span className="spinner-border spinner-border-sm" aria-hidden="true" />
							<T id="dashboard.metrics.updating" />
						</span>
					)}
					<div className={styles.rangeGroup} role="group" aria-labelledby="security-traffic-heading">
						{RANGES.map((value) => (
							<button
								key={value}
								type="button"
								className={cn(styles.rangeButton, range === value && styles.rangeButtonSelected)}
								aria-pressed={range === value}
								onClick={() => setRange(value)}
							>
								<T id={`dashboard.range.${value}`} />
							</button>
						))}
					</div>
				</div>
			</div>

			{isLoading ? (
				<div className={cn("card", styles.stateCard)}>
					<div className="card-body">
						<Loading noLogo />
					</div>
				</div>
			) : isError && !data ? (
				<div className={cn("card", styles.stateCard)}>
					<div className="card-body">
						<div className="alert alert-danger mb-0" role="alert">
							<T id="dashboard.metrics.error" />
							<div>
								<Button className={styles.retryButton} onClick={() => refetch()}>
									<T id="dashboard.metrics.error-retry" />
								</Button>
							</div>
						</div>
					</div>
				</div>
			) : (
				data &&
				(disabled ? (
					<div className={styles.disabledGrid}>
						<div className="alert alert-info mb-0" role="status">
							<T id="dashboard.metrics.disabled" />
						</div>
						<Posture report={data} />
					</div>
				) : (
					<>
						<Summary report={data} />
						{isError && (
							<div className="alert alert-warning mb-0" role="alert">
								<T id="dashboard.metrics.error" />
								<Button className={styles.inlineRetryButton} onClick={() => refetch()}>
									<T id="dashboard.metrics.error-retry" />
								</Button>
							</div>
						)}
						{noVisibleHosts ? (
							<div className="alert alert-info mb-0" role="status">
								<T id="dashboard.metrics.no-visible-hosts" />
							</div>
						) : (
							noTraffic && (
								<div className="alert alert-info mb-0" role="status">
									<T id="dashboard.metrics.empty" />
								</div>
							)
						)}
						<div className={styles.insightsGrid}>
							<Trend
								series={fillSeriesGaps(data.series, data.range, data.generatedAt)}
								range={data.range}
							/>
							<Posture report={data} />
						</div>
						<div className={styles.tablesGrid}>
							<TopHosts report={data} />
							<TopSources report={data} />
						</div>
					</>
				))
			)}
		</section>
	);
};

interface SectionProps {
	report: DashboardReport;
}

const Summary = ({ report }: SectionProps) => {
	const { traffic } = report;
	return (
		<section aria-labelledby="metrics-summary-heading">
			<h4 id="metrics-summary-heading" className={styles.sectionLabel}>
				<T id="dashboard.metrics.summary" />
			</h4>
			<div className={styles.metricGrid}>
				<MetricCard
					label={<T id="dashboard.metrics.requests" />}
					value={formatNumber(traffic.requests)}
					icon={<IconActivity aria-hidden="true" />}
					tone="blue"
				/>
				<MetricCard
					label={<T id="dashboard.metrics.bandwidth" />}
					value={formatBytes(traffic.bytesSent)}
					icon={<IconDatabaseExport aria-hidden="true" />}
					tone="azure"
				/>
				<MetricCard
					label={<T id="dashboard.metrics.client-errors" />}
					value={formatNumber(traffic.status4xx)}
					icon={<IconAlertTriangle aria-hidden="true" />}
					tone="yellow"
				/>
				<MetricCard
					label={<T id="dashboard.metrics.server-errors" />}
					value={formatNumber(traffic.status5xx)}
					icon={<IconServerOff aria-hidden="true" />}
					tone="red"
				/>
			</div>
		</section>
	);
};

interface MetricCardProps {
	label: React.ReactNode;
	value: string;
	icon: React.ReactNode;
	tone: "blue" | "azure" | "yellow" | "red";
}

const METRIC_TONES = {
	blue: styles.metricBlue,
	azure: styles.metricAzure,
	yellow: styles.metricYellow,
	red: styles.metricRed,
};

const MetricCard = ({ label, value, icon, tone }: MetricCardProps) => (
	<div className={cn("card", styles.metricCard, METRIC_TONES[tone])}>
		<div className="card-body">
			<div className="d-flex align-items-start justify-content-between gap-3">
				<div className="min-w-0">
					<div className="subheader">{label}</div>
					<div className={styles.metricValue}>{value}</div>
				</div>
				<span className={styles.metricIcon}>{icon}</span>
			</div>
		</div>
	</div>
);

const Trend = ({ series, range }: { series: DashboardSeriesPoint[]; range: DashboardRange }) => {
	const max = maxSeriesRequests(series);
	const labelIndexes = new Set([0, Math.floor((series.length - 1) / 2), series.length - 1]);

	return (
		<section className="card" aria-labelledby="metrics-trend-heading">
			<div className="card-header">
				<h4 id="metrics-trend-heading" className="card-title">
					<T id="dashboard.metrics.trend" />
				</h4>
			</div>
			<div className={cn("card-body", styles.chartBody)}>
				{series.length === 0 ? (
					<p className={styles.note}>
						<T id="dashboard.metrics.no-data" />
					</p>
				) : (
					<>
						<div className={styles.chartPlot}>
							<div className={styles.chartGrid} aria-hidden="true" />
							<div
								className={styles.chart}
								role="img"
								aria-labelledby="metrics-trend-heading"
								data-range={range}
							>
								{series.map((point) => {
									const total = Math.max(1, point.requestCount);
									const heightPct = max > 0 ? (point.requestCount / max) * 100 : 0;
									return (
										<div
											key={point.bucketStart}
											className={styles.bar}
											style={{ height: `${heightPct}%` }}
											title={`${formatBucketLabel(point.bucketStart, range)}: ${formatNumber(point.requestCount)}`}
										>
											{point.status2xx > 0 && (
												<div
													className={styles.bar2xx}
													style={{ height: `${(point.status2xx / total) * 100}%` }}
												/>
											)}
											{point.status3xx > 0 && (
												<div
													className={styles.bar3xx}
													style={{ height: `${(point.status3xx / total) * 100}%` }}
												/>
											)}
											{point.status4xx > 0 && (
												<div
													className={styles.bar4xx}
													style={{ height: `${(point.status4xx / total) * 100}%` }}
												/>
											)}
											{point.status5xx > 0 && (
												<div
													className={styles.bar5xx}
													style={{ height: `${(point.status5xx / total) * 100}%` }}
												/>
											)}
											{point.status1xx > 0 && (
												<div
													className={styles.bar1xx}
													style={{ height: `${(point.status1xx / total) * 100}%` }}
												/>
											)}
										</div>
									);
								})}
							</div>
						</div>
						<div className={styles.chartLabels} aria-hidden="true">
							{series.map((point, index) => (
								<span key={point.bucketStart}>
									{labelIndexes.has(index) ? formatBucketLabel(point.bucketStart, range) : ""}
								</span>
							))}
						</div>
						<div className={styles.legend}>
							<LegendItem className={styles.bar1xx} id="dashboard.metrics.status-1xx" />
							<LegendItem className={styles.bar2xx} id="dashboard.metrics.status-2xx" />
							<LegendItem className={styles.bar3xx} id="dashboard.metrics.status-3xx" />
							<LegendItem className={styles.bar4xx} id="dashboard.metrics.status-4xx" />
							<LegendItem className={styles.bar5xx} id="dashboard.metrics.status-5xx" />
						</div>
						{/* This table communicates the chart data without relying on color. */}
						<div className={styles.srOnly}>
							<table>
								<caption>
									<T id="dashboard.metrics.trend" />
								</caption>
								<thead>
									<tr>
										<th scope="col">
											<T id="dashboard.metrics.bucket" />
										</th>
										<th scope="col">
											<T id="dashboard.metrics.requests" />
										</th>
										<th scope="col">1xx</th>
										<th scope="col">2xx</th>
										<th scope="col">3xx</th>
										<th scope="col">4xx</th>
										<th scope="col">5xx</th>
									</tr>
								</thead>
								<tbody>
									{series.map((point) => (
										<tr key={point.bucketStart}>
											<td>{formatBucketLabel(point.bucketStart, range)}</td>
											<td>{point.requestCount}</td>
											<td>{point.status1xx}</td>
											<td>{point.status2xx}</td>
											<td>{point.status3xx}</td>
											<td>{point.status4xx}</td>
											<td>{point.status5xx}</td>
										</tr>
									))}
								</tbody>
							</table>
						</div>
					</>
				)}
			</div>
		</section>
	);
};

const LegendItem = ({ className, id }: { className: string; id: string }) => (
	<span className={styles.legendItem}>
		<span className={cn(styles.legendSwatch, className)} aria-hidden="true" />
		<T id={id} />
	</span>
);

const POSTURE_ROWS: { key: keyof DashboardReport["posture"]; id: string }[] = [
	{ key: "enabled", id: "dashboard.posture.enabled" },
	{ key: "disabled", id: "dashboard.posture.disabled" },
	{ key: "certificateConfigured", id: "dashboard.posture.certificate-configured" },
	{ key: "forcedHttps", id: "dashboard.posture.forced-https" },
	{ key: "effectiveHsts", id: "dashboard.posture.effective-hsts" },
	{ key: "exploitRulesEnabled", id: "dashboard.posture.exploit-rules" },
	{ key: "accessControlled", id: "dashboard.posture.access-controlled" },
	{ key: "certificatesExpiring", id: "dashboard.posture.certificates-expiring" },
	{ key: "certificatesExpired", id: "dashboard.posture.certificates-expired" },
];

const Posture = ({ report }: SectionProps) => (
	<section className="card" aria-labelledby="metrics-posture-heading">
		<div className="card-header">
			<div>
				<h4 id="metrics-posture-heading" className="card-title">
					<T id="dashboard.posture.title" />
				</h4>
				<p className={cn("card-subtitle", styles.postureNote)}>
					<T id="dashboard.posture.note" />
				</p>
			</div>
		</div>
		<dl className={cn("list-group list-group-flush", styles.postureList)}>
			{POSTURE_ROWS.map((row) => (
				<div key={row.key} className="list-group-item">
					<dt>
						<T id={row.id} />
					</dt>
					<dd className="mb-0">{formatNumber(report.posture[row.key])}</dd>
				</div>
			))}
		</dl>
	</section>
);

const TopHosts = ({ report }: SectionProps) => (
	<section className="card" aria-labelledby="metrics-top-hosts-heading">
		<div className="card-header">
			<h4 id="metrics-top-hosts-heading" className="card-title">
				<T id="dashboard.metrics.top-hosts" />
			</h4>
		</div>
		{report.topHosts.length === 0 ? (
			<div className="card-body">
				<p className={styles.note}>
					<T id="dashboard.metrics.no-data" />
				</p>
			</div>
		) : (
			<div className="table-responsive">
				<table className={cn("table table-vcenter card-table", styles.table)}>
					<thead>
						<tr>
							<th scope="col">
								<T id="dashboard.metrics.host" />
							</th>
							<th scope="col" className="text-end">
								<T id="dashboard.metrics.requests" />
							</th>
							<th scope="col" className="text-end">
								<T id="dashboard.metrics.bandwidth" />
							</th>
							<th scope="col" className="text-end">
								4xx
							</th>
							<th scope="col" className="text-end">
								5xx
							</th>
						</tr>
					</thead>
					<tbody>
						{report.topHosts.map((host) => (
							<tr key={host.id}>
								<td className={styles.domainCell}>{host.domain}</td>
								<td className="text-end">{formatNumber(host.requestCount)}</td>
								<td className="text-end">{formatBytes(host.bytesSent)}</td>
								<td className="text-end">{formatNumber(host.status4xx)}</td>
								<td className="text-end">{formatNumber(host.status5xx)}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		)}
	</section>
);

const TopSources = ({ report }: SectionProps) => (
	<section className="card" aria-labelledby="metrics-top-sources-heading">
		<div className="card-header">
			<div>
				<h4 id="metrics-top-sources-heading" className="card-title">
					<T id="dashboard.metrics.top-sources" />
				</h4>
				<p className="card-subtitle">
					<T id="dashboard.metrics.source-note" />
				</p>
			</div>
		</div>
		{report.topSources.items.length === 0 ? (
			<div className="card-body">
				<p className={styles.note}>
					<T id="dashboard.metrics.no-data" />
				</p>
			</div>
		) : (
			<div className="table-responsive">
				<table className={cn("table table-vcenter card-table", styles.table)}>
					<thead>
						<tr>
							<th scope="col">
								<T id="dashboard.metrics.source-ip" />
							</th>
							<th scope="col">
								<T id="dashboard.metrics.host" />
							</th>
							<th scope="col" className="text-end">
								4xx
							</th>
							<th scope="col" className="text-end">
								5xx
							</th>
							<th scope="col" className="text-end">
								<T id="dashboard.metrics.total" />
							</th>
						</tr>
					</thead>
					<tbody>
						{report.topSources.items.map((source) => (
							<tr key={`${source.clientIp}-${source.proxyHostId}`}>
								<td className="text-nowrap font-monospace">{source.clientIp}</td>
								<td className={styles.domainCell}>{source.domain}</td>
								<td className="text-end">{formatNumber(source.status4xx)}</td>
								<td className="text-end">{formatNumber(source.status5xx)}</td>
								<td className="text-end fw-medium">{formatNumber(source.observedCount)}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		)}
	</section>
);

export default SecurityTrafficDashboard;
