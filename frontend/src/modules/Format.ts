import { getLocale } from "src/locale";

/**
 * Locale-aware formatting shared by every page that shows counts.
 *
 * `Intl` throws on a locale tag it does not recognise, and the locale here
 * comes from user preference, so each of these falls back to the unformatted
 * value rather than taking the page down.
 */
export const formatNumber = (value: number | null | undefined): string => {
	const number = value ?? 0;
	try {
		return new Intl.NumberFormat(getLocale()).format(number);
	} catch {
		return String(number);
	}
};

export const formatBytes = (bytes: number): string => {
	if (!bytes) {
		return "0 B";
	}
	const units = ["B", "KB", "MB", "GB", "TB"];
	const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
	const value = bytes / 1024 ** i;
	try {
		return `${new Intl.NumberFormat(getLocale(), { maximumFractionDigits: 1 }).format(value)} ${units[i]}`;
	} catch {
		return `${value} ${units[i]}`;
	}
};

/** Epoch milliseconds as a local date and time, or an em dash when absent. */
export const formatDateTime = (value: number | string | null | undefined): string => {
	if (value === null || value === undefined || value === "") {
		return "—";
	}
	const date = new Date(value);
	if (Number.isNaN(date.getTime())) {
		return String(value);
	}
	try {
		return new Intl.DateTimeFormat(getLocale(), { dateStyle: "medium", timeStyle: "medium" }).format(date);
	} catch {
		return date.toLocaleString();
	}
};

/** A duration in milliseconds as the coarsest unit that stays readable. */
export const formatDuration = (ms: number): string => {
	if (ms < 1000) {
		return `${Math.round(ms)}ms`;
	}
	if (ms < 60_000) {
		return `${Math.round(ms / 1000)}s`;
	}
	if (ms < 3_600_000) {
		return `${Math.round(ms / 60_000)}m`;
	}
	return `${Math.round(ms / 3_600_000)}h`;
};
