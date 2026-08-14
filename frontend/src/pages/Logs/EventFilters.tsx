import { IconX } from "@tabler/icons-react";
import { format } from "date-fns";
import { useEffect } from "react";
import type { SecurityEventType, SecurityRange, SecuritySeverity } from "src/api/backend";
import { useProxyHosts } from "src/hooks";
import { intl, T } from "src/locale";
import styles from "./Logs.module.css";

export const RANGE_MS: Record<SecurityRange, number> = { "24h": 86400000, "7d": 7 * 86400000, "30d": 30 * 86400000 };
const PRESETS: SecurityRange[] = ["24h", "7d", "30d"];
export const EVENT_TYPES: SecurityEventType[] = ["exploit_rule", "http_status", "nginx_error"];
export const SEVERITIES: SecuritySeverity[] = ["low", "medium", "high", "critical"];

/** Structural filters live in the URL so a view can be linked to. */
const CHIP_FIELDS = [
	"proxyHostId",
	"eventType",
	"severity",
	"clientIp",
	"ruleId",
	"status",
	"statusClass",
	"method",
] as const;

const LOCAL_INPUT = "yyyy-MM-dd'T'HH:mm";
const toLocalInput = (ms: number) => format(new Date(ms), LOCAL_INPUT);
const fromLocalInput = (value: string) => {
	const parsed = new Date(value).getTime();
	return Number.isNaN(parsed) ? null : parsed;
};

export interface FilterProps {
	params: URLSearchParams;
	update: (changes: Record<string, string | null>) => void;
	text: string;
	onText: (value: string) => void;
}

/**
 * The window is always materialised into explicit `from`/`to` millisecond
 * bounds, even when it started as a preset. A window recomputed from
 * `Date.now()` on every render changes the query key on every render, and the
 * page would refetch forever.
 */
export const useMaterializedWindow = (params: URLSearchParams, update: FilterProps["update"]) => {
	const from = params.get("from");
	const to = params.get("to");
	// biome-ignore lint/correctness/useExhaustiveDependencies: only the absence of an explicit window should trigger this.
	useEffect(() => {
		if (from && to) return;
		const preset = (params.get("range") as SecurityRange) || "24h";
		const now = Date.now();
		update({ range: preset, from: String(now - (RANGE_MS[preset] ?? RANGE_MS["24h"])), to: String(now) });
	}, [from, to]);
	return { from, to };
};

export const Input = ({
	label,
	value,
	onChange,
	inputMode,
	type = "text",
}: {
	label: string;
	value: string;
	onChange: (value: string) => void;
	inputMode?: "numeric";
	type?: string;
}) => {
	const id = `logs-${label}`;
	return (
		<div>
			<label htmlFor={id} className="form-label">
				{intl.formatMessage({ id: label })}
			</label>
			<input
				id={id}
				type={type}
				className="form-control"
				value={value}
				inputMode={inputMode}
				onChange={(event) => onChange(event.target.value)}
			/>
		</div>
	);
};

export const Select = ({
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
}) => {
	const id = `logs-${label}`;
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
};

function EventFilters({ params, update, text, onText }: FilterProps) {
	const { data: hosts = [] } = useProxyHosts();
	const from = Number(params.get("from"));
	const to = Number(params.get("to"));
	const preset = params.get("range") as SecurityRange | null;
	const hostName = (id: string) => hosts.find((host) => String(host.id) === id)?.domainNames.join(", ") || `#${id}`;
	const chips = CHIP_FIELDS.flatMap((field) => {
		const value = params.get(field);
		if (!value) return [];
		return [{ field, label: field === "proxyHostId" ? hostName(value) : value }];
	});
	const clearAll = () =>
		update({
			...Object.fromEntries(CHIP_FIELDS.map((field) => [field, null])),
			includeOperational: null,
			cursor: null,
		});

	return (
		<div className={styles.filterPanel}>
			<div className={styles.rangeRow}>
				{/* Two hand-typed epoch-millisecond boxes were the previous control. */}
				<div className="btn-group" role="group" aria-label={intl.formatMessage({ id: "security.time-range" })}>
					{PRESETS.map((value) => (
						<button
							type="button"
							key={value}
							className={`btn btn-sm ${preset === value ? "btn-primary" : "btn-outline-primary"}`}
							aria-pressed={preset === value}
							onClick={() => {
								const now = Date.now();
								update({
									range: value,
									from: String(now - RANGE_MS[value]),
									to: String(now),
									cursor: null,
								});
							}}
						>
							<T id={`dashboard.range.${value}`} />
						</button>
					))}
					<button
						type="button"
						className={`btn btn-sm ${preset ? "btn-outline-primary" : "btn-primary"}`}
						aria-pressed={!preset}
						onClick={() => update({ range: null, cursor: null })}
					>
						<T id="logs.custom-range" />
					</button>
				</div>
				{preset ? null : (
					<div className={styles.customRange}>
						<Input
							label="security.from"
							type="datetime-local"
							value={from ? toLocalInput(from) : ""}
							onChange={(value) => {
								const parsed = fromLocalInput(value);
								if (parsed !== null) update({ from: String(parsed), cursor: null });
							}}
						/>
						<Input
							label="security.to"
							type="datetime-local"
							value={to ? toLocalInput(to) : ""}
							onChange={(value) => {
								const parsed = fromLocalInput(value);
								if (parsed !== null) update({ to: String(parsed), cursor: null });
							}}
						/>
					</div>
				)}
				<label className="form-check form-switch mb-0">
					<input
						className="form-check-input"
						type="checkbox"
						checked={params.get("includeOperational") === "true"}
						onChange={(event) =>
							update({ includeOperational: event.target.checked ? "true" : null, cursor: null })
						}
					/>
					<span className="form-check-label">
						<T id="logs.include-operational" />
					</span>
				</label>
			</div>

			<div className={styles.filters}>
				<Select
					label="security.host"
					value={params.get("proxyHostId") || ""}
					onChange={(value) => update({ proxyHostId: value || null, cursor: null })}
					options={hosts.map((host) => [String(host.id), host.domainNames.join(", ") || `#${host.id}`])}
				/>
				<Select
					label="security.type"
					value={params.get("eventType") || ""}
					onChange={(value) => update({ eventType: value || null, cursor: null })}
					options={EVENT_TYPES.map((value) => [value, value])}
				/>
				<Select
					label="security.severity"
					value={params.get("severity") || ""}
					onChange={(value) => update({ severity: value || null, cursor: null })}
					options={SEVERITIES.map((value) => [
						value,
						intl.formatMessage({ id: `security.severity.${value}` }),
					])}
				/>
				<Input
					label="security.source-ip"
					value={params.get("clientIp") || ""}
					onChange={(value) => update({ clientIp: value || null, cursor: null })}
				/>
				<Input
					label="security.rule"
					value={params.get("ruleId") || ""}
					onChange={(value) => update({ ruleId: value || null, cursor: null })}
				/>
				<Input
					label="security.status"
					inputMode="numeric"
					value={params.get("status") || ""}
					onChange={(value) => update({ status: value || null, cursor: null })}
				/>
				<Input
					label="security.method"
					value={params.get("method") || ""}
					onChange={(value) => update({ method: value.toUpperCase() || null, cursor: null })}
				/>
				{/* Kept out of the URL: query strings can carry tokens or credentials. */}
				<Input label="security.metadata-search" value={text} onChange={onText} />
			</div>

			{chips.length ? (
				<div className={styles.chips}>
					{chips.map((chip) => (
						<button
							type="button"
							key={chip.field}
							className="badge bg-blue-lt"
							onClick={() => update({ [chip.field]: null, cursor: null })}
							aria-label={`${intl.formatMessage({ id: "logs.remove-filter" })}: ${chip.label}`}
						>
							{chip.label} <IconX size={12} aria-hidden="true" />
						</button>
					))}
					<button type="button" className="btn btn-sm btn-ghost-secondary" onClick={clearAll}>
						<T id="logs.clear-filters" />
					</button>
				</div>
			) : null}
		</div>
	);
}

export default EventFilters;
