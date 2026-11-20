import { IconArrowRight } from "@tabler/icons-react";
import { Link } from "react-router-dom";
import type { SecurityEventFilters, SecurityFinding, SecurityFindingReport } from "src/api/backend";
import { Loading, QueryError, SeverityBadge } from "src/components";
import { T } from "src/locale";
import { formatDateTime, formatNumber } from "src/modules/Format";
import styles from "./Security.module.css";

/**
 * A finding's evidence is exactly the events the detector counted, so the
 * backend ships the filter that reproduces them and this turns it into a /logs
 * query string. No filter is reconstructed here from the finding's prose --
 * that is how a "view evidence" link drifts from what it claims to show.
 */
const evidenceHref = (filter: SecurityEventFilters) => {
	const params = new URLSearchParams({ tab: "events" });
	for (const [key, value] of Object.entries(filter)) {
		if (value !== null && value !== undefined && value !== "") params.set(key, String(value));
	}
	return `/logs?${params.toString()}`;
};

const subjectLabel = (finding: SecurityFinding) =>
	finding.subject.clientIp ??
	finding.subject.hostDomain ??
	(finding.subject.proxyHostId ? `#${finding.subject.proxyHostId}` : "—");

/**
 * Every detector's numbers, flattened for the message formatter. Values a given
 * message does not reference are simply unused, which keeps one call site
 * instead of a switch over seven shapes.
 */
const summaryValues = (finding: SecurityFinding) => ({
	source: finding.subject.clientIp ?? "—",
	host: finding.subject.hostDomain ?? (finding.subject.proxyHostId ? `#${finding.subject.proxyHostId}` : "—"),
	count: finding.evidenceCount,
	uris: finding.metrics.distinctUris ?? 0,
	hosts: finding.metrics.distinctHosts ?? 0,
	rules: finding.metrics.distinctRules ?? 0,
	baseline: finding.metrics.baselinePerHour ?? 0,
});

const FindingRow = ({ finding }: { finding: SecurityFinding }) => (
	<article className={styles.finding}>
		<div className={styles.findingHead}>
			<SeverityBadge severity={finding.severity} />
			<h4 className={styles.findingTitle}>
				<T id={`security.finding.${finding.type}`} />
			</h4>
			{finding.operational ? (
				<span className="badge bg-blue-lt">
					<T id="security.operational" />
				</span>
			) : null}
		</div>
		<p className={styles.findingSummary}>
			<T id={`security.finding.${finding.type}.summary`} data={summaryValues(finding)} />
		</p>
		<dl className={styles.findingMeta}>
			<div>
				<dt>
					<T id="security.subject" />
				</dt>
				<dd className="font-monospace">{subjectLabel(finding)}</dd>
			</div>
			<div>
				<dt>
					<T id="security.first-seen" />
				</dt>
				<dd>{formatDateTime(finding.firstSeen)}</dd>
			</div>
			<div>
				<dt>
					<T id="security.last-seen" />
				</dt>
				<dd>{formatDateTime(finding.lastSeen)}</dd>
			</div>
			<div>
				<dt>
					<T id="security.evidence-count" />
				</dt>
				<dd>{formatNumber(finding.evidenceCount)}</dd>
			</div>
		</dl>
		<Link className="btn btn-sm btn-outline-primary" to={evidenceHref(finding.filter)}>
			<T id="security.view-evidence" /> <IconArrowRight aria-hidden="true" />
		</Link>
	</article>
);

interface FindingsProps {
	report?: SecurityFindingReport;
	isLoading: boolean;
	isError: boolean;
	onRetry: () => void;
}

const Findings = ({ report, isLoading, isError, onRetry }: FindingsProps) => (
	<section className="card mt-3" aria-labelledby="security-findings-heading">
		<div className="card-header">
			<div>
				<h3 id="security-findings-heading" className="card-title">
					<T id="security.findings" />
				</h3>
				<p className="card-subtitle">
					<T id="security.findings-note" />
				</p>
			</div>
		</div>
		<div className="card-body">
			{isLoading ? (
				<Loading noLogo />
			) : isError ? (
				<QueryError onRetry={onRetry} />
			) : report?.findings.length ? (
				<>
					<div className={styles.findingList}>
						{report.findings.map((finding) => (
							<FindingRow key={finding.id} finding={finding} />
						))}
					</div>
					{report.truncated ? (
						<p className="text-secondary mt-3 mb-0">
							<T id="security.findings-truncated" />
						</p>
					) : null}
				</>
			) : (
				<p className="text-secondary mb-0">
					<T id="security.findings-empty" />
				</p>
			)}
		</div>
	</section>
);

export { evidenceHref };
export default Findings;
