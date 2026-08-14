import EasyModal, { type InnerModalProps } from "ez-modal-react";
import Modal from "react-bootstrap/Modal";
import type { SecurityEvent } from "src/api/backend";
import { Button, Loading, SeverityBadge } from "src/components";
import { useSecurityEvent } from "src/hooks";
import { T } from "src/locale";
import { formatDateTime } from "src/modules/Format";
import styles from "./Logs.module.css";

const showEventDetailsModal = (event: SecurityEvent) => {
	EasyModal.show(EventDetailsModal, { event });
};

const stringValue = (value: string | number | null | undefined) =>
	value === null || value === undefined || value === "" ? "—" : String(value);

interface Props extends InnerModalProps {
	event: SecurityEvent;
}

/**
 * The list projection carries thirteen columns; the full record carries forty.
 * The detail read fetches the rest, but the row already in hand is rendered
 * meanwhile so the panel is never empty.
 *
 * Every value here is rendered as text, never as markup or a link: request
 * URIs, user agents, and referrers are attacker-controlled by definition.
 */
const EventDetailsModal = EasyModal.create(({ event, visible, remove }: Props) => {
	const detail = useSecurityEvent(event.eventId);
	const record = detail.data || event;
	const fields: [string, string | number | null | undefined][] = [
		["security.time", record.occurredAtMs],
		["security.ingested-at", record.createdOn],
		["security.event-id", record.eventId],
		["security.request-id", record.requestId],
		["security.schema-version", record.schemaVersion],
		["security.ruleset-version", record.rulesetVersion],
		["security.type", record.eventType],
		["security.rule", record.ruleId],
		["security.rule-category", record.ruleCategory],
		["security.rule-action", record.ruleAction],
		["security.source-ip", record.clientIp],
		["security.peer-ip", record.peerIp],
		["security.peer-port", record.peerPort],
		["security.host", record.requestHost || record.hostDomainSnapshot],
		["security.method", record.method],
		["security.scheme", record.scheme],
		["security.protocol", record.httpProtocol],
		["security.uri", record.requestUri],
		["security.status", record.status],
		["security.upstream-status", record.upstreamStatus],
		["security.request-bytes", record.requestBytes],
		["security.response-bytes", record.responseBytes],
		["security.duration", record.requestTimeMs],
		["security.upstream-address", record.upstreamAddr],
		["security.upstream-duration", record.upstreamTimeMs],
		["security.tls-protocol", record.tlsProtocol],
		["security.tls-cipher", record.tlsCipher],
		["security.remote-user", record.remoteUser],
		["security.user-agent", record.userAgent],
		["security.referrer", record.referrer],
		["security.nginx-level", record.nginxErrorLevel],
		["security.nginx-message", record.nginxErrorMessage],
	];
	return (
		<Modal show={visible} onHide={remove} size="lg" scrollable>
			<Modal.Header closeButton>
				<Modal.Title>
					<T id="security.event-details" /> <SeverityBadge severity={record.severity} />
				</Modal.Title>
			</Modal.Header>
			<Modal.Body>
				{detail.isError ? (
					<p className="alert alert-warning">
						<T id="security.detail-unavailable" />
					</p>
				) : null}
				{detail.isLoading ? <Loading noLogo /> : null}
				<div className={styles.detailGrid}>
					{fields.map(([label, value]) => (
						<div key={label}>
							<strong>
								<T id={label} />
							</strong>
							<div className={styles.detailValue}>
								{label === "security.time" ? formatDateTime(value as number) : stringValue(value)}
							</div>
						</div>
					))}
				</div>
			</Modal.Body>
			<Modal.Footer>
				<Button data-bs-dismiss="modal" onClick={remove}>
					<T id="action.close" />
				</Button>
			</Modal.Footer>
		</Modal>
	);
});

export { showEventDetailsModal, stringValue };
