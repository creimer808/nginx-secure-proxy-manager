import { createColumnHelper, getCoreRowModel, useReactTable } from "@tanstack/react-table";
import { useMemo, useState } from "react";
import type { SecurityEvent, SecurityEventFilters, SecurityEventType, SecuritySeverity } from "src/api/backend";
import { Loading, QueryError, SeverityBadge } from "src/components";
import { TableLayout } from "src/components/Table/TableLayout";
import { useSecurityEvents } from "src/hooks";
import { intl, T } from "src/locale";
import { formatDateTime } from "src/modules/Format";
import EventFilters, { useMaterializedWindow } from "./EventFilters";
import { showEventDetailsModal, stringValue } from "./EventDetails";
import styles from "./Logs.module.css";

const toNumber = (value: string | null): number | undefined =>
	value && /^\d+$/.test(value) ? Number(value) : undefined;

const columnHelper = createColumnHelper<SecurityEvent>();

const useColumns = () =>
	useMemo(
		() => [
			columnHelper.accessor("occurredAtMs", {
				header: intl.formatMessage({ id: "security.time" }),
				cell: (info) => <span className="text-nowrap">{formatDateTime(info.getValue())}</span>,
			}),
			columnHelper.accessor("severity", {
				header: intl.formatMessage({ id: "security.severity" }),
				cell: (info) => <SeverityBadge severity={info.getValue()} />,
				meta: { className: "w-1" },
			}),
			columnHelper.accessor("eventType", {
				header: intl.formatMessage({ id: "security.type" }),
				cell: (info) => info.getValue(),
			}),
			columnHelper.accessor("ruleId", {
				header: intl.formatMessage({ id: "security.rule" }),
				cell: (info) => <span className="font-monospace">{stringValue(info.getValue())}</span>,
			}),
			columnHelper.accessor("clientIp", {
				header: intl.formatMessage({ id: "security.source-ip" }),
				cell: (info) => <span className="font-monospace text-nowrap">{stringValue(info.getValue())}</span>,
			}),
			columnHelper.accessor("hostDomainSnapshot", {
				header: intl.formatMessage({ id: "security.host" }),
				cell: (info) => stringValue(info.getValue()),
			}),
			columnHelper.accessor("method", {
				header: intl.formatMessage({ id: "security.method" }),
				cell: (info) => stringValue(info.getValue()),
			}),
			columnHelper.accessor("requestUri", {
				header: intl.formatMessage({ id: "security.uri" }),
				cell: (info) => <span className={styles.uriCell}>{stringValue(info.getValue())}</span>,
			}),
			columnHelper.accessor("userAgent", {
				header: intl.formatMessage({ id: "security.user-agent" }),
				cell: (info) => <span className={styles.uriCell}>{stringValue(info.getValue())}</span>,
			}),
			columnHelper.accessor("status", {
				header: intl.formatMessage({ id: "security.status" }),
				cell: (info) => stringValue(info.getValue()),
			}),
			columnHelper.display({
				id: "details",
				cell: (info) => (
					<button
						type="button"
						className="btn btn-action btn-sm px-1"
						aria-label={`${intl.formatMessage({ id: "action.view-details" })}: ${info.row.original.requestUri || info.row.original.eventId}`}
						onClick={() => showEventDetailsModal(info.row.original)}
					>
						<T id="action.view-details" />
					</button>
				),
				meta: { className: "text-end w-1" },
			}),
		],
		[],
	);

interface EventsProps {
	params: URLSearchParams;
	update: (changes: Record<string, string | null>) => void;
}

function Events({ params, update }: EventsProps) {
	// Metadata search stays in component state: a query string can contain a
	// token or a credential, and the URL is copied, bookmarked, and logged.
	const [text, setText] = useState("");
	const [previousCursors, setPreviousCursors] = useState<string[]>([]);
	useMaterializedWindow(params, update);
	const filters = useMemo<SecurityEventFilters>(
		() => ({
			from: params.get("from") || undefined,
			to: params.get("to") || undefined,
			proxyHostId: toNumber(params.get("proxyHostId")),
			eventType: (params.get("eventType") as SecurityEventType) || undefined,
			severity: (params.get("severity") as SecuritySeverity) || undefined,
			ruleId: params.get("ruleId") || undefined,
			clientIp: params.get("clientIp") || undefined,
			status: toNumber(params.get("status")),
			statusClass: params.get("statusClass") === "5xx" ? "5xx" : undefined,
			method: params.get("method") || undefined,
			includeOperational: params.get("includeOperational") === "true" ? "true" : undefined,
			query: text || undefined,
			cursor: params.get("cursor") || undefined,
		}),
		[params, text],
	);
	const ready = Boolean(params.get("from") && params.get("to"));
	const { data, isLoading, isError, refetch, isFetching } = useSecurityEvents(filters, ready);
	const columns = useColumns();
	const table = useReactTable<SecurityEvent>({
		columns,
		data: data?.items ?? [],
		getCoreRowModel: getCoreRowModel(),
		rowCount: data?.items.length ?? 0,
		meta: { isFetching },
		enableSortingRemoval: false,
	});

	return (
		<section aria-labelledby="logs-events-heading">
			<h3 id="logs-events-heading">
				<T id="security.events" />
			</h3>
			<p className="text-secondary">
				<T id="security.query-warning" />
			</p>
			<EventFilters
				params={params}
				update={update}
				text={text}
				onText={(value) => {
					setText(value);
					setPreviousCursors([]);
					update({ cursor: null });
				}}
			/>
			{!ready || isLoading ? (
				<Loading noLogo />
			) : isError ? (
				<QueryError onRetry={() => refetch()} />
			) : (
				<div className="card">
					<TableLayout
						tableInstance={table}
						emptyState={
							<tr>
								<td colSpan={columns.length} className="text-center text-secondary p-3">
									<T id="security.empty" />
								</td>
							</tr>
						}
					/>
				</div>
			)}
			{isFetching && (
				<span role="status" className="text-secondary">
					<T id="dashboard.metrics.updating" />
				</span>
			)}
			<div className="d-flex gap-2 mt-3">
				{previousCursors.length > 0 && (
					<button
						type="button"
						className="btn btn-outline-primary"
						onClick={() => {
							const previous = previousCursors[previousCursors.length - 1];
							setPreviousCursors((items) => items.slice(0, -1));
							update({ cursor: previous || null });
						}}
					>
						<T id="security.previous-page" />
					</button>
				)}
				{data?.nextCursor && (
					<button
						type="button"
						className="btn btn-primary"
						onClick={() => {
							setPreviousCursors((items) => [...items, params.get("cursor") || ""]);
							update({ cursor: data.nextCursor });
						}}
					>
						<T id="security.next-page" />
					</button>
				)}
			</div>
		</section>
	);
}

export default Events;
