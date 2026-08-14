import { IconAlertTriangle, IconShieldCheck, IconServer, IconUsers } from "@tabler/icons-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import type { SecurityCollectorHealth, SecurityCountItem, SecurityOverview, SecurityRange } from "src/api/backend";
import {
	LoadingPage,
	MetricCard,
	MetricGrid,
	QueryError,
	RangeSelector,
	type TrendBucket,
	TrendChart,
	type TrendSeriesKey,
} from "src/components";
import { useSecurityFindings, useSecurityOverview } from "src/hooks";
import { getLocale, T } from "src/locale";
import { formatDuration, formatNumber } from "src/modules/Format";
import Findings from "./Findings";
import styles from "./Security.module.css";

/**
 * Nginx buckets every record by the hour. A month of hourly bars is 720 of
 * them, which is a texture rather than a chart, so longer ranges are re-bucketed
 * by day here instead of asking the backend for a second grouping.
 */
const BUCKETS: Record<SecurityRange, { size: number; count: number }> = {
	"24h": { size: 3600000, count: 24 },
	"7d": { size: 86400000, count: 8 },
	"30d": { size: 86400000, count: 31 },
};

const SEVERITY_SERIES: TrendSeriesKey[] = [
	{ id: "low", tone: "secondary", label: <T id="security.severity.low" />, shortLabel: "low" },
	{ id: "medium", tone: "yellow", label: <T id="security.severity.medium" />, shortLabel: "medium" },
	{ id: "high", tone: "orange", label: <T id="security.severity.high" />, shortLabel: "high" },
	{ id: "critical", tone: "red", label: <T id="security.severity.critical" />, shortLabel: "critical" },
];

const bucketLabel = (start: number, range: SecurityRange) => {
	try {
		return new Intl.DateTimeFormat(
			getLocale(),
			range === "24h" ? { hour: "numeric" } : { month: "short", day: "numeric" },
		).format(new Date(start));
	} catch {
		return String(start);
	}
};

const timelineBuckets = (data: SecurityOverview, range: SecurityRange): TrendBucket[] => {
	const { size, count } = BUCKETS[range];
	const end = Math.floor(Date.now() / size) * size;
	const start = end - (count - 1) * size;
	const totals = new Map<number, Record<string, number>>();
	for (const point of data.timeline) {
		const bucket = Math.floor(point.bucketStart / size) * size;
		if (bucket < start) continue;
		const values = totals.get(bucket) ?? {};
		values[point.severity] = (values[point.severity] || 0) + point.count;
		totals.set(bucket, values);
	}
	return Array.from({ length: count }, (_, index) => {
		const bucket = start + index * size;
		return { key: bucket, label: bucketLabel(bucket, range), values: totals.get(bucket) ?? {} };
	});
};

/**
 * Collector health was a permanent banner, which trains an operator to ignore
 * it. Healthy is a pill; degraded expands into something that has to be read.
 */
const Collector = ({ health }: { health: SecurityCollectorHealth }) => {
	const notes = [
		health.limitReached ? <T key="limit" id="security.collector-limit" /> : null,
		health.databaseHighWaterReached ? <T key="db" id="security.collector-database-full" /> : null,
		health.rawLogDiskHighWaterReached ? <T key="disk" id="security.collector-disk-full" /> : null,
		health.lastErrorSummary ? <span key="error">{health.lastErrorSummary}</span> : null,
	].filter(Boolean);
	const stopped = health.enabled === false || health.available === false;
	if (!stopped && !notes.length) {
		return (
			<span className={`badge bg-green-lt ${styles.collectorPill}`}>
				<T id="security.collector-available" />
				{health.lagMs !== undefined && health.lagMs !== null ? ` · ${formatDuration(health.lagMs)}` : ""}
			</span>
		);
	}
	return (
		<div
			className={`alert ${stopped ? "alert-warning" : "alert-info"} mb-0 ${styles.collectorAlert}`}
			role="status"
		>
			<strong>
				<T id="security.collector-health" />:
			</strong>{" "}
			{health.enabled === false ? (
				<T id="security.collector-disabled" />
			) : health.available === false ? (
				<T id="security.collector-unavailable" />
			) : (
				<T id="security.collector-degraded" />
			)}
			{notes.length ? (
				<ul className="mb-0">
					{notes.map((note, index) => (
						<li key={String(index)}>{note}</li>
					))}
				</ul>
			) : null}
		</div>
	);
};

const Top = ({
	title,
	values,
	field,
	range,
}: {
	title: string;
	values: SecurityCountItem[];
	field: "ruleId" | "clientIp";
	range: SecurityRange;
}) => (
	<section className="col-lg-6">
		<div className="card h-100">
			<div className="card-header">
				<h3 className="card-title">
					<T id={title} />
				</h3>
			</div>
			{values.length ? (
				<div className="table-responsive">
					<table className="table table-sm table-vcenter card-table">
						<tbody>
							{values.map((value) => (
								<tr key={String(value[field])}>
									<td>
										<Link
											to={`/logs?tab=events&range=${range}&${field}=${encodeURIComponent(String(value[field]))}`}
										>
											{String(value[field])}
										</Link>
									</td>
									<td className="text-end">{formatNumber(value.count)}</td>
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

function Overview() {
	const [range, setRange] = useState<SecurityRange>("24h");
	const overview = useSecurityOverview(range);
	const findings = useSecurityFindings(range);
	if (overview.isLoading) return <LoadingPage noLogo />;
	if (overview.isError || !overview.data) return <QueryError onRetry={() => overview.refetch()} />;
	const data = overview.data;
	const open = findings.data?.findings.filter((finding) => !finding.operational) ?? [];
	const urgent = open.filter((finding) => finding.severity === "critical" || finding.severity === "high").length;

	return (
		<section aria-labelledby="security-overview-heading">
			<div className="d-flex justify-content-between align-items-center gap-2 flex-wrap">
				<div className="d-flex align-items-center gap-2 flex-wrap">
					<h3 id="security-overview-heading" className="mb-0">
						<T id="security.overview" />
					</h3>
					<Collector health={data.collector} />
				</div>
				<RangeSelector value={range} onChange={setRange} />
			</div>
			<div className="mt-3">
				<MetricGrid>
					<MetricCard
						label={<T id="security.open-findings" />}
						value={formatNumber(open.length)}
						hint={urgent ? <T id="security.urgent-findings" data={{ count: urgent }} /> : undefined}
						icon={<IconAlertTriangle aria-hidden="true" />}
						tone={urgent ? "red" : "green"}
					/>
					<MetricCard
						label={<T id="security.rule-matches" />}
						value={formatNumber(data.exploitRuleMatches)}
						icon={<IconShieldCheck aria-hidden="true" />}
						tone="azure"
					/>
					<MetricCard
						label={<T id="security.distinct-sources" />}
						value={formatNumber(data.distinctSources)}
						icon={<IconUsers aria-hidden="true" />}
						tone="blue"
					/>
					<MetricCard
						label={<T id="security.hosts-affected" />}
						value={formatNumber(data.distinctHosts)}
						icon={<IconServer aria-hidden="true" />}
						tone="yellow"
					/>
				</MetricGrid>
			</div>
			<Findings
				report={findings.data}
				isLoading={findings.isLoading}
				isError={findings.isError}
				onRetry={() => findings.refetch()}
			/>
			<div className="mt-3">
				<TrendChart
					headingId="security-timeline-heading"
					title={<T id="security.timeline" />}
					subtitle={<T id="security.timeline-note" />}
					series={SEVERITY_SERIES}
					buckets={timelineBuckets(data, range)}
					emptyLabel={<T id="security.empty" />}
					bucketHeading={<T id="security.time" />}
					totalHeading={<T id="security.count" />}
				/>
			</div>
			<div className="row row-cards mt-3">
				<Top title="security.top-sources" values={data.topSources} field="clientIp" range={range} />
				<Top title="security.top-rules" values={data.topRules} field="ruleId" range={range} />
			</div>
		</section>
	);
}

export default Overview;
