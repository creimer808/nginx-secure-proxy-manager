import { useState } from "react";
import { Button, Loading } from "src/components";
import { useDashboardReport } from "src/hooks";
import { getLocale, T } from "src/locale";
import type { DashboardRange, DashboardReport, DashboardSeriesPoint } from "src/api/backend";
import cn from "classnames";
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

const maxSeriesRequests = (series: DashboardSeriesPoint[]): number =>
	series.reduce((max, point) => Math.max(max, point.requestCount), 0);

const SecurityTrafficDashboard = () => {
	const [range, setRange] = useState<DashboardRange>("24h");
	const { data, isLoading, isError, isFetching, refetch } = useDashboardReport(range);

	const disabled = data && data.collection.enabled === false;
	const noTraffic = !!data && data.traffic.requests === 0 && data.series.length === 0;

	return (
		<div className="card">
			<div className="card-body">
				<div className="d-flex flex-wrap justify-content-between align-items-center gap-2">
					<h3>
						<T id="dashboard.metrics.title" />
					</h3>
					<div className={styles.rangeGroup} role="group" aria-label="metric range">
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

				{isLoading ? (
					<Loading noLogo />
				) : isError ? (
					<div className="alert alert-danger" role="alert">
						<T id="dashboard.metrics.error" />
						<div>
							<Button className={styles.retryButton} onClick={() => refetch()}>
								<T id="dashboard.metrics.error-retry" />
							</Button>
						</div>
					</div>
				) : (
					data && (
						<>
							{isFetching && (
								<div className={styles.note}>
									<T id="dashboard.metrics.updating" />
								</div>
							)}
							{disabled ? (
								<>
									<p className={styles.note}>
										<T id="dashboard.metrics.disabled" />
									</p>
									<Posture report={data} />
								</>
							) : (
								<>
									<Summary report={data} />
									<Trend series={data.series} range={range} />
									<Posture report={data} />
									<TopHosts report={data} />
									<TopSources report={data} />
									{noTraffic && (
										<p className={styles.note}>
											<T id="dashboard.metrics.empty" />
										</p>
									)}
								</>
							)}
						</>
					)
				)}
			</div>
		</div>
	);
};

interface SectionProps {
	report: DashboardReport;
}

const Summary = ({ report }: SectionProps) => {
	const { traffic } = report;
	return (
		<section aria-labelledby="metrics-summary-heading">
			<h4 id="metrics-summary-heading" className="mt-3">
				<T id="dashboard.metrics.summary" />
			</h4>
			<div className={styles.metricGrid}>
				<MetricCard label={<T id="dashboard.metrics.requests" />} value={formatNumber(traffic.requests)} />
				<MetricCard label={<T id="dashboard.metrics.bandwidth" />} value={formatBytes(traffic.bytesSent)} />
				<MetricCard label={<T id="dashboard.metrics.client-errors" />} value={formatNumber(traffic.status4xx)} />
				<MetricCard label={<T id="dashboard.metrics.server-errors" />} value={formatNumber(traffic.status5xx)} />
			</div>
		</section>
	);
};

interface MetricCardProps {
	label: React.ReactNode;
	value: string;
}

const MetricCard = ({ label, value }: MetricCardProps) => (
	<div className={styles.metricCard}>
		<div className={styles.metricValue}>{value}</div>
		<div className={styles.metricLabel}>{label}</div>
	</div>
);

const Trend = ({ series, range }: { series: DashboardSeriesPoint[]; range: DashboardRange }) => {
	const max = maxSeriesRequests(series);
	return (
		<section aria-labelledby="metrics-trend-heading">
			<h4 id="metrics-trend-heading">
				<T id="dashboard.metrics.trend" />
			</h4>
			{series.length === 0 ? (
				<p className={styles.note}>
					<T id="dashboard.metrics.no-data" />
				</p>
			) : (
				<>
					<div
						className={styles.chart}
						role="img"
						aria-label={`${series.length} ${range} buckets`}
					>
						{series.map((point) => {
							const total = Math.max(1, point.requestCount);
							const heightPct = max > 0 ? (point.requestCount / max) * 100 : 0;
							return (
								<div
									key={point.bucketStart}
									className={styles.bar}
									style={{ height: `${heightPct}%` }}
									title={`${formatNumber(point.requestCount)}`}
								>
									{point.status2xx > 0 && (
										<div className={styles.bar2xx} style={{ height: `${(point.status2xx / total) * 100}%` }} />
									)}
									{point.status3xx > 0 && (
										<div className={styles.bar3xx} style={{ height: `${(point.status3xx / total) * 100}%` }} />
									)}
									{point.status4xx > 0 && (
										<div className={styles.bar4xx} style={{ height: `${(point.status4xx / total) * 100}%` }} />
									)}
									{point.status5xx > 0 && (
										<div className={styles.bar5xx} style={{ height: `${(point.status5xx / total) * 100}%` }} />
									)}
									{point.status1xx > 0 && (
										<div className={styles.bar1xx} style={{ height: `${(point.status1xx / total) * 100}%` }} />
									)}
								</div>
							);
						})}
					</div>
					<div className={styles.legend}>
						<LegendItem className={styles.bar1xx} id="dashboard.metrics.status-1xx" />
						<LegendItem className={styles.bar2xx} id="dashboard.metrics.status-2xx" />
						<LegendItem className={styles.bar3xx} id="dashboard.metrics.status-3xx" />
						<LegendItem className={styles.bar4xx} id="dashboard.metrics.status-4xx" />
						<LegendItem className={styles.bar5xx} id="dashboard.metrics.status-5xx" />
					</div>
					{/* Accessible table fallback: communicates the same data without relying on color. */}
					<div className={styles.srOnly}>
						<table className={styles.table}>
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
										<td>{point.bucketStart}</td>
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
	<section aria-labelledby="metrics-posture-heading">
		<h4 id="metrics-posture-heading">
			<T id="dashboard.posture.title" />
		</h4>
		<p className={styles.note}>
			<T id="dashboard.posture.note" />
		</p>
		<dl className={styles.postureGrid}>
			{POSTURE_ROWS.map((row) => (
				<div key={row.key} className={styles.postureItem}>
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
	<section aria-labelledby="metrics-top-hosts-heading" className="mt-3">
		<h4 id="metrics-top-hosts-heading">
			<T id="dashboard.metrics.top-hosts" />
		</h4>
		{report.topHosts.length === 0 ? (
			<p className={styles.note}>
				<T id="dashboard.metrics.no-data" />
			</p>
		) : (
			<div className="table-responsive">
				<table className={styles.table}>
					<thead>
						<tr>
							<th scope="col">
								<T id="dashboard.metrics.host" />
							</th>
							<th scope="col">
								<T id="dashboard.metrics.requests" />
							</th>
							<th scope="col">
								<T id="dashboard.metrics.bandwidth" />
							</th>
							<th scope="col">4xx</th>
							<th scope="col">5xx</th>
						</tr>
					</thead>
					<tbody>
						{report.topHosts.map((host) => (
							<tr key={host.id}>
								<td>{host.domain}</td>
								<td>{formatNumber(host.requestCount)}</td>
								<td>{formatBytes(host.bytesSent)}</td>
								<td>{host.status4xx}</td>
								<td>{host.status5xx}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		)}
	</section>
);

const TopSources = ({ report }: SectionProps) => (
	<section aria-labelledby="metrics-top-sources-heading" className="mt-3">
		<h4 id="metrics-top-sources-heading">
			<T id="dashboard.metrics.top-sources" />
		</h4>
		<p className={styles.note}>
			<T id="dashboard.metrics.source-note" />
		</p>
		{report.topSources.items.length === 0 ? (
			<p className={styles.note}>
				<T id="dashboard.metrics.no-data" />
			</p>
		) : (
			<div className="table-responsive">
				<table className={styles.table}>
					<thead>
						<tr>
							<th scope="col">
								<T id="dashboard.metrics.source-ip" />
							</th>
							<th scope="col">
								<T id="dashboard.metrics.host" />
							</th>
							<th scope="col">4xx</th>
							<th scope="col">5xx</th>
							<th scope="col">
								<T id="dashboard.metrics.total" />
							</th>
						</tr>
					</thead>
					<tbody>
						{report.topSources.items.map((source) => (
							<tr key={`${source.clientIp}-${source.proxyHostId}`}>
								<td>{source.clientIp}</td>
								<td>{source.domain}</td>
								<td>{source.status4xx}</td>
								<td>{source.status5xx}</td>
								<td>{formatNumber(source.observedCount)}</td>
							</tr>
						))}
					</tbody>
				</table>
			</div>
		)}
	</section>
);

export default SecurityTrafficDashboard;
