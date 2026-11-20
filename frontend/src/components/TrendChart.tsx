import cn from "classnames";
import type { ReactNode } from "react";
import { formatNumber } from "src/modules/Format";
import styles from "./TrendChart.module.css";

export type TrendTone = "secondary" | "green" | "azure" | "yellow" | "orange" | "red";

const TREND_TONES: Record<TrendTone, string> = {
	secondary: styles.toneSecondary,
	green: styles.toneGreen,
	azure: styles.toneAzure,
	yellow: styles.toneYellow,
	orange: styles.toneOrange,
	red: styles.toneRed,
};

export interface TrendSeriesKey {
	id: string;
	tone: TrendTone;
	label: ReactNode;
	/** Short plain-text heading for the accessible data table. */
	shortLabel: string;
}

export interface TrendBucket {
	key: string | number;
	label: string;
	/** Segment totals by series id. Missing ids are treated as zero. */
	values: Record<string, number>;
	/**
	 * Bar height and reported total. Defaults to the sum of the segments; pass it
	 * explicitly where the source counts records the segments do not classify,
	 * so the bar is not shorter than the number printed beside it.
	 */
	total?: number;
}

interface TrendChartProps {
	headingId: string;
	title: ReactNode;
	subtitle?: ReactNode;
	series: TrendSeriesKey[];
	buckets: TrendBucket[];
	emptyLabel: ReactNode;
	bucketHeading: ReactNode;
	totalHeading: ReactNode;
	/** Stamped on the plot as `data-range`, so a test can tell which window is drawn. */
	range?: string;
}

const bucketTotal = (bucket: TrendBucket, series: TrendSeriesKey[]) =>
	bucket.total ?? series.reduce((sum, key) => sum + (bucket.values[key.id] || 0), 0);

/**
 * A stacked bar chart in CSS. No charting library: the data is a few dozen
 * buckets of small integers, and a dependency that ships its own canvas
 * renderer to draw rectangles is not worth the bundle.
 *
 * Colour alone never carries the data — the same numbers are published as a
 * visually hidden table below the plot.
 */
export const TrendChart = ({
	headingId,
	title,
	subtitle,
	series,
	buckets,
	emptyLabel,
	bucketHeading,
	totalHeading,
	range,
}: TrendChartProps) => {
	const max = buckets.reduce((highest, bucket) => Math.max(highest, bucketTotal(bucket, series)), 0);
	const labelIndexes = new Set([0, Math.floor((buckets.length - 1) / 2), buckets.length - 1]);

	return (
		<section className="card" aria-labelledby={headingId}>
			<div className="card-header">
				<div>
					<h4 id={headingId} className="card-title">
						{title}
					</h4>
					{subtitle ? <p className="card-subtitle">{subtitle}</p> : null}
				</div>
			</div>
			<div className={cn("card-body", styles.chartBody)}>
				{buckets.length === 0 || max === 0 ? (
					<p className={styles.note}>{emptyLabel}</p>
				) : (
					<>
						<div className={styles.chartPlot}>
							<div className={styles.chartGrid} aria-hidden="true" />
							<div className={styles.chart} role="img" aria-labelledby={headingId} data-range={range}>
								{buckets.map((bucket) => {
									const total = bucketTotal(bucket, series);
									return (
										<div
											key={bucket.key}
											className={styles.bar}
											style={{ height: `${(total / max) * 100}%` }}
											title={`${bucket.label}: ${formatNumber(total)}`}
										>
											{series.map((key) =>
												bucket.values[key.id] ? (
													<div
														key={key.id}
														className={TREND_TONES[key.tone]}
														style={{
															height: `${(bucket.values[key.id] / Math.max(1, total)) * 100}%`,
														}}
													/>
												) : null,
											)}
										</div>
									);
								})}
							</div>
						</div>
						<div className={styles.chartLabels} aria-hidden="true">
							{buckets.map((bucket, index) => (
								<span key={bucket.key}>{labelIndexes.has(index) ? bucket.label : ""}</span>
							))}
						</div>
						<div className={styles.legend}>
							{series.map((key) => (
								<span key={key.id} className={styles.legendItem}>
									<span
										className={cn(styles.legendSwatch, TREND_TONES[key.tone])}
										aria-hidden="true"
									/>
									{key.label}
								</span>
							))}
						</div>
						<div className={styles.srOnly}>
							<table>
								<caption>{title}</caption>
								<thead>
									<tr>
										<th scope="col">{bucketHeading}</th>
										<th scope="col">{totalHeading}</th>
										{series.map((key) => (
											<th scope="col" key={key.id}>
												{key.shortLabel}
											</th>
										))}
									</tr>
								</thead>
								<tbody>
									{buckets.map((bucket) => (
										<tr key={bucket.key}>
											<td>{bucket.label}</td>
											<td>{bucketTotal(bucket, series)}</td>
											{series.map((key) => (
												<td key={key.id}>{bucket.values[key.id] || 0}</td>
											))}
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
