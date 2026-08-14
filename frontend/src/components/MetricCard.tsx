import cn from "classnames";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import styles from "./MetricCard.module.css";

export type MetricTone = "blue" | "azure" | "green" | "yellow" | "orange" | "red";

const METRIC_TONES: Record<MetricTone, string> = {
	blue: styles.metricBlue,
	azure: styles.metricAzure,
	green: styles.metricGreen,
	yellow: styles.metricYellow,
	orange: styles.metricOrange,
	red: styles.metricRed,
};

interface MetricCardProps {
	label: ReactNode;
	value: string;
	/** Secondary line under the value: a comparison, a unit, or a caveat. */
	hint?: ReactNode;
	icon?: ReactNode;
	tone?: MetricTone;
	/** Turns the card into a router link. Mutually exclusive with `onClick`. */
	to?: string;
	onClick?: () => void;
}

const Body = ({ label, value, hint, icon }: Pick<MetricCardProps, "label" | "value" | "hint" | "icon">) => (
	<div className="card-body">
		<div className="d-flex align-items-start justify-content-between gap-3">
			<div className="min-w-0">
				<div className="subheader">{label}</div>
				<div className={styles.metricValue}>{value}</div>
				{hint ? <div className={styles.metricHint}>{hint}</div> : null}
			</div>
			{icon ? <span className={styles.metricIcon}>{icon}</span> : null}
		</div>
	</div>
);

/**
 * The single stat tile used by the dashboard and the security overview. It was
 * duplicated as an ad-hoc `card card-sm` in one place and a styled card in the
 * other; a stat that can be clicked through to its evidence is common enough to
 * belong to one component.
 */
export const MetricCard = ({ label, value, hint, icon, tone = "blue", to, onClick }: MetricCardProps) => {
	const className = cn("card", styles.metricCard, METRIC_TONES[tone]);
	if (to) {
		return (
			<Link to={to} className={cn(className, styles.metricAction)}>
				<Body label={label} value={value} hint={hint} icon={icon} />
			</Link>
		);
	}
	if (onClick) {
		return (
			<button type="button" className={cn(className, styles.metricAction)} onClick={onClick}>
				<Body label={label} value={value} hint={hint} icon={icon} />
			</button>
		);
	}
	return (
		<div className={className}>
			<Body label={label} value={value} hint={hint} icon={icon} />
		</div>
	);
};

/** Responsive row for a set of MetricCards. */
export const MetricGrid = ({ children }: { children: ReactNode }) => (
	<div className={styles.metricGrid}>{children}</div>
);
