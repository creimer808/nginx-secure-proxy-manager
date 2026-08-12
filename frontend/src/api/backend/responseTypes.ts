import type { AppVersion, User } from "./models";

export interface HealthResponse {
	status: string;
	version: AppVersion;
	setup: boolean;
}

export interface TokenResponse {
	expires: number;
	token: string;
}

export interface ValidatedCertificateResponse {
	certificate: Record<string, any>;
	certificateKey: boolean;
}

export interface LoginAsTokenResponse extends TokenResponse {
	user: User;
}

export interface VersionCheckResponse {
	current: string | null;
	latest: string | null;
	updateAvailable: boolean;
}

export interface TwoFactorChallengeResponse {
	requires2fa: boolean;
	challengeToken: string;
}

export interface TwoFactorStatusResponse {
	enabled: boolean;
	backupCodesRemaining: number;
}

export interface TwoFactorSetupResponse {
	secret: string;
	otpauthUrl: string;
}

export interface TwoFactorEnableResponse {
	backupCodes: string[];
}

export type DashboardRange = "24h" | "7d" | "30d";

export interface DashboardSeriesPoint {
	bucketStart: number;
	requestCount: number;
	status1xx: number;
	status2xx: number;
	status3xx: number;
	status4xx: number;
	status5xx: number;
}

export interface DashboardTopHost {
	id: number;
	domain: string;
	requestCount: number;
	bytesSent: number;
	status4xx: number;
	status5xx: number;
}

export interface DashboardTopSource {
	clientIp: string;
	proxyHostId: number;
	domain: string;
	status4xx: number;
	status5xx: number;
	observedCount: number;
}

export interface DashboardReport {
	range: DashboardRange;
	generatedAt: number;
	collection: {
		enabled: boolean;
	};
	posture: {
		enabled: number;
		disabled: number;
		certificateConfigured: number;
		forcedHttps: number;
		effectiveHsts: number;
		exploitRulesEnabled: number;
		accessControlled: number;
		certificatesExpired: number;
		certificatesExpiring: number;
	};
	traffic: {
		requests: number;
		bytesSent: number;
		status1xx: number;
		status2xx: number;
		status3xx: number;
		status4xx: number;
		status5xx: number;
	};
	series: DashboardSeriesPoint[];
	topHosts: DashboardTopHost[];
	topSources: {
		approximate: boolean;
		items: DashboardTopSource[];
	};
}
