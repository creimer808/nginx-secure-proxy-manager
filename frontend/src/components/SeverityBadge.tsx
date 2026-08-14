import type { SecuritySeverity } from "src/api/backend";
import { T } from "src/locale";

const SEVERITY_CLASS: Record<SecuritySeverity, string> = {
	low: "bg-secondary",
	medium: "bg-yellow",
	high: "bg-orange",
	critical: "bg-red",
};

/**
 * Severity is ordinal, so it is shown as a graded chip rather than as raw text.
 * The label carries the meaning; the colour only reinforces it.
 */
export const SeverityBadge = ({ severity }: { severity: SecuritySeverity }) => (
	<span className={`badge ${SEVERITY_CLASS[severity] ?? "bg-secondary"} text-white`}>
		<T id={`security.severity.${severity}`} />
	</span>
);
