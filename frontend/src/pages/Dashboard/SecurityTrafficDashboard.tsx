import { IconActivity, IconAlertTriangle, IconDatabaseExport, IconServerOff, IconShieldSearch } from "@tabler/icons-react";
import cn from "classnames";
import { useState } from "react";
import { Link } from "react-router-dom";
import type { DashboardRange, DashboardReport, DashboardSeriesPoint } from "src/api/backend";
import { Button, Loading, MetricCard, MetricGrid, TrendChart, type TrendSeriesKey } from "src/components";
import { useDashboardReport, useSecurityFindings } from "src/hooks";
import { getLocale, T } from "src/locale";
import { formatBytes, formatNumber } from "src/modules/Format";
import styles from "./Dashboard.module.css";

const RANGES: DashboardRange[] = ["24h", "7d", "30d"];

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
					{/* A router link, not an anchor: the anchor here threw away the whole
					    SPA and reloaded the application just to change page. */}
					<Link to="/security" className="small">
						<T id="dashboard.metrics.open-security" />
					</Link>
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

/**
 * Findings are computed over the security event tables rather than the traffic
 * aggregates, so this tile is its own query. It is deliberately quiet when the
 * request fails: a missing findings count must not take the traffic dashboard
 * down with it.
 */
const OpenFindings = ({ range }: { range: DashboardRange }) => {
	const { data } = useSecurityFindings(range);
	if (!data) {
		return null;
	}
	const urgent = data.counts.critical + data.counts.high;
	return (
		<MetricCard
			label={<T id="dashboard.metrics.open-findings" />}
			value={formatNumber(data.findings.length)}
			hint={urgent ? <T id="dashboard.metrics.urgent-findings" data={{ count: urgent }} /> : undefined}
			icon={<IconShieldSearch aria-hidden="true" />}
			tone={urgent ? "orange" : "green"}
			to="/security"
		/>
	);
};

const Summary = ({ report }: SectionProps) => {
	const { traffic } = report;
	return (
		<section aria-labelledby="metrics-summary-heading">
			<h4 id="metrics-summary-heading" className={styles.sectionLabel}>
				<T id="dashboard.metrics.summary" />
			</h4>
			<MetricGrid>
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
				<OpenFindings range={report.range} />
			</MetricGrid>
		</section>
	);
};

const TREND_SERIES: TrendSeriesKey[] = [
	{ id: "status1xx", tone: "secondary", label: <T id="dashboard.metrics.status-1xx" />, shortLabel: "1xx" },
	{ id: "status2xx", tone: "green", label: <T id="dashboard.metrics.status-2xx" />, shortLabel: "2xx" },
	{ id: "status3xx", tone: "azure", label: <T id="dashboard.metrics.status-3xx" />, shortLabel: "3xx" },
	{ id: "status4xx", tone: "yellow", label: <T id="dashboard.metrics.status-4xx" />, shortLabel: "4xx" },
	{ id: "status5xx", tone: "red", label: <T id="dashboard.metrics.status-5xx" />, shortLabel: "5xx" },
];

const Trend = ({ series, range }: { series: DashboardSeriesPoint[]; range: DashboardRange }) => (
	<TrendChart
		headingId="metrics-trend-heading"
		title={<T id="dashboard.metrics.trend" />}
		series={TREND_SERIES}
		buckets={series.map((point) => ({
			key: point.bucketStart,
			label: formatBucketLabel(point.bucketStart, range),
			total: point.requestCount,
			values: {
				status1xx: point.status1xx,
				status2xx: point.status2xx,
				status3xx: point.status3xx,
				status4xx: point.status4xx,
				status5xx: point.status5xx,
			},
		}))}
		range={range}
		emptyLabel={<T id="dashboard.metrics.no-data" />}
		bucketHeading={<T id="dashboard.metrics.bucket" />}
		totalHeading={<T id="dashboard.metrics.requests" />}
	/>
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
