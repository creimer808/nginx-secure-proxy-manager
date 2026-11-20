import { useEffect } from "react";

/**
 * Suppresses the Referer header for the lifetime of the mounted page.
 *
 * This matters on the security and logs pages specifically: their URLs carry
 * filters over request metadata -- source addresses, rule ids, matched paths --
 * and a referrer would leak those to anything the user navigates out to.
 */
export const useNoReferrer = () => {
	useEffect(() => {
		let meta = document.querySelector<HTMLMetaElement>('meta[name="referrer"]');
		if (!meta) {
			meta = document.createElement("meta");
			meta.name = "referrer";
			document.head.append(meta);
		}
		const previous = meta.content;
		meta.content = "no-referrer";
		return () => {
			meta.content = previous;
		};
	}, []);
};
