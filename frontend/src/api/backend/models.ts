export interface AppVersion {
	major: number;
	minor: number;
	revision: number;
}

export interface ApplicationVersions {
	appVersion: string;
	upstreamVersion: string;
}

export interface UserPermissions {
	id?: number;
	createdOn?: string;
	modifiedOn?: string;
	userId?: number;
	visibility: string;
	proxyHosts: string;
	redirectionHosts: string;
	deadHosts: string;
	streams: string;
	accessLists: string;
	certificates: string;
}

export interface User {
	id: number;
	createdOn: string;
	modifiedOn: string;
	isDisabled: boolean;
	email: string;
	name: string;
	nickname: string;
	avatar: string;
	roles: string[];
	permissions?: UserPermissions;
}

export interface AuditLog {
	id: number;
	createdOn: string;
	modifiedOn: string;
	userId: number;
	objectType: string;
	objectId: number;
	action: string;
	meta: Record<string, any>;
	// Expansions:
	user?: User;
}

export interface AccessList {
	id?: number;
	createdOn?: string;
	modifiedOn?: string;
	ownerUserId: number;
	name: string;
	meta: Record<string, any>;
	satisfyAny: boolean;
	passAuth: boolean;
	proxyHostCount?: number;
	// Expansions:
	owner?: User;
	items?: AccessListItem[];
	clients?: AccessListClient[];
}

export interface AccessListItem {
	id?: number;
	createdOn?: string;
	modifiedOn?: string;
	accessListId?: number;
	username: string;
	password: string;
	meta?: Record<string, any>;
	hint?: string;
}

export type AccessListClient = {
	id?: number;
	createdOn?: string;
	modifiedOn?: string;
	accessListId?: number;
	address: string;
	directive: "allow" | "deny";
	meta?: Record<string, any>;
};

export interface Certificate {
	id: number;
	createdOn: string;
	modifiedOn: string;
	ownerUserId: number;
	provider: string;
	niceName: string;
	domainNames: string[];
	expiresOn: string;
	meta: Record<string, any>;
	owner?: User;
	proxyHosts?: ProxyHost[];
	deadHosts?: DeadHost[];
	redirectionHosts?: RedirectionHost[];
}

export interface ProxyLocation {
	path: string;
	advancedConfig: string;
	forwardScheme: string;
	forwardHost: string;
	forwardPort: number;
}

export interface ProxyHost {
	id: number;
	createdOn: string;
	modifiedOn: string;
	ownerUserId: number;
	domainNames: string[];
	forwardScheme: string;
	forwardHost: string;
	forwardPort: number;
	accessListId: number;
	certificateId: number;
	sslForced: boolean;
	cachingEnabled: boolean;
	blockExploits: boolean;
	advancedConfig: string;
	meta: Record<string, any>;
	allowWebsocketUpgrade: boolean;
	http2Support: boolean;
	enabled: boolean;
	locations?: ProxyLocation[];
	hstsEnabled: boolean;
	hstsSubdomains: boolean;
	trustForwardedProto: boolean;
	// Expansions:
	owner?: User;
	accessList?: AccessList;
	certificate?: Certificate;
}

export interface DeadHost {
	id: number;
	createdOn: string;
	modifiedOn: string;
	ownerUserId: number;
	domainNames: string[];
	certificateId: number;
	sslForced: boolean;
	advancedConfig: string;
	meta: Record<string, any>;
	http2Support: boolean;
	enabled: boolean;
	hstsEnabled: boolean;
	hstsSubdomains: boolean;
	// Expansions:
	owner?: User;
	certificate?: Certificate;
}

export interface RedirectionHost {
	id: number;
	createdOn: string;
	modifiedOn: string;
	ownerUserId: number;
	domainNames: string[];
	forwardDomainName: string;
	preservePath: boolean;
	certificateId: number;
	sslForced: boolean;
	blockExploits: boolean;
	advancedConfig: string;
	meta: Record<string, any>;
	http2Support: boolean;
	forwardScheme: string;
	forwardHttpCode: number;
	enabled: boolean;
	hstsEnabled: boolean;
	hstsSubdomains: boolean;
	// Expansions:
	owner?: User;
	certificate?: Certificate;
}

export interface Stream {
	id: number;
	createdOn: string;
	modifiedOn: string;
	ownerUserId: number;
	incomingPort: number;
	forwardingHost: string;
	forwardingPort: number;
	tcpForwarding: boolean;
	udpForwarding: boolean;
	meta: Record<string, any>;
	enabled: boolean;
	certificateId: number;
	// Expansions:
	owner?: User;
	certificate?: Certificate;
}

export interface Setting {
	id: string;
	name?: string;
	description?: string;
	value: string;
	meta?: Record<string, any>;
}

export interface DNSProvider {
	id: string;
	name: string;
	credentials: string;
}

export type SecurityRange = "24h" | "7d" | "30d";
export type SecurityEventType = "exploit_rule" | "http_status" | "nginx_error";
export type SecuritySeverity = "low" | "medium" | "high" | "critical";
export type SecurityLogKind = "access" | "error" | "security";
export type SecurityLogTarget = "host" | "global";

export interface SecurityCollectorHealth {
	enabled?: boolean;
	available?: boolean;
	lagMs?: number | null;
	lastStartedOn?: string | null;
	lastCompletedOn?: string | null;
	lastErrorOn?: string | null;
	lastErrorSummary?: string | null;
	bytesRead?: number;
	linesRead?: number;
	eventsInserted?: number;
	estimatedDatabaseBytes?: number;
	malformedLines?: number;
	filesPending?: number;
	limitReached?: boolean;
	databaseHighWaterReached?: boolean;
	rawLogDiskHighWaterReached?: boolean;
}

export interface SecurityCountItem {
	count: number;
	ruleId?: string;
	clientIp?: string;
	proxyHostId?: number;
	status?: number;
	method?: string;
}

export interface SecurityTimelineItem {
	bucketStart: number;
	eventType: SecurityEventType;
	severity: SecuritySeverity;
	count: number;
}

export interface SecurityOverview {
	range: SecurityRange;
	totalEvents: number;
	exploitRuleMatches: number;
	nginxErrors: number;
	statuses: { "401": number; "403": number; "404": number; "429": number; "5xx": number };
	timeline: SecurityTimelineItem[];
	topRules: SecurityCountItem[];
	topSources: SecurityCountItem[];
	topHosts: SecurityCountItem[];
	topStatuses: SecurityCountItem[];
	topMethods: SecurityCountItem[];
	collector: SecurityCollectorHealth;
}

export interface SecurityEvent {
	id: number;
	eventId: string | null;
	occurredAtMs: number;
	createdOn?: string;
	proxyHostId: number | null;
	hostDomainSnapshot: string | null;
	ownerUserIdSnapshot?: number | null;
	sourceKind: string;
	schemaVersion?: string | null;
	rulesetVersion?: string | null;
	requestId?: string | null;
	eventType: SecurityEventType;
	severity: SecuritySeverity;
	ruleId: string | null;
	ruleCategory?: string | null;
	ruleAction?: string | null;
	clientIp: string | null;
	peerIp?: string | null;
	peerPort?: number | null;
	method: string | null;
	scheme?: string | null;
	requestHost?: string | null;
	requestUri: string | null;
	httpProtocol?: string | null;
	status: number | null;
	upstreamStatus?: string | null;
	requestBytes?: number | null;
	responseBytes?: number | null;
	requestTimeMs: number | null;
	upstreamAddr?: string | null;
	upstreamTimeMs?: number | null;
	tlsProtocol?: string | null;
	tlsCipher?: string | null;
	remoteUser?: string | null;
	userAgent?: string | null;
	referrer?: string | null;
	nginxErrorLevel?: string | null;
	nginxErrorMessage?: string | null;
}

export interface SecurityEventPage { items: SecurityEvent[]; nextCursor: string | null; }
export interface SecurityRule { id: string; category: string; description: string; action: string; rulesetVersion: string; count: number; }
export interface SecurityLogFile { rotation: string; compressed: boolean; available: boolean; }
export interface SecurityLogLine { offset: number; line: string; }
export interface SecurityLogPage { lines: SecurityLogLine[]; partial: boolean; scanLimitBytes: number; nextCursor: string | null; previousCursor: string | null; }
/** Outcome of the startup proxy-host configuration upgrade. Administrators only. */
export interface SecurityNginxUpgrade { lastRunOn: string | null; hostsTotal: number; hostsUpgraded: number; hostsSkipped: number; hostsPending: number; reloadDeferred: boolean; lastErrorSummary: string | null; }
export interface SecuritySettings { retentionDays: number; nginxUpgrade?: SecurityNginxUpgrade | null; }

export interface SecurityEventFilters {
	from?: string;
	to?: string;
	proxyHostId?: number;
	eventType?: SecurityEventType;
	severity?: SecuritySeverity;
	ruleId?: string;
	clientIp?: string;
	status?: number;
	statusClass?: "5xx";
	method?: string;
	query?: string;
	limit?: number;
	cursor?: string;
}
