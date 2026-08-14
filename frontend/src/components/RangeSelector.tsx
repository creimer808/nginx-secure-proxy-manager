import type { SecurityRange } from "src/api/backend";
import { intl, T } from "src/locale";

const RANGES: SecurityRange[] = ["24h", "7d", "30d"];

interface RangeSelectorProps {
	value: SecurityRange;
	onChange: (range: SecurityRange) => void;
}

/**
 * Tabler's `.btn` carries no margin of its own and a JSX map emits no
 * whitespace text nodes, so these need `.btn-group` to sit together.
 */
export const RangeSelector = ({ value, onChange }: RangeSelectorProps) => (
	<div className="btn-group" role="group" aria-label={intl.formatMessage({ id: "security.time-range" })}>
		{RANGES.map((range) => (
			<button
				type="button"
				key={range}
				className={`btn btn-sm ${value === range ? "btn-primary" : "btn-outline-primary"}`}
				aria-pressed={value === range}
				onClick={() => onChange(range)}
			>
				<T id={`dashboard.range.${range}`} />
			</button>
		))}
	</div>
);
