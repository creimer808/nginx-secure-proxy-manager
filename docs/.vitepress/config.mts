import { defineConfig } from "vitepress";

const title = "Nginx Secure Proxy Manager";
const description = "A security-focused Nginx Proxy Manager fork with traffic visibility";

export default defineConfig({
	title,
	description,
	head: [
		["link", { rel: "icon", href: "/icon.png" }],
		["meta", { name: "description", content: description }],
		["meta", { property: "og:title", content: title }],
		["meta", { property: "og:description", content: description }],
		["meta", { property: "og:type", content: "website" }],
		["meta", { name: "twitter:card", content: "summary" }],
		["meta", { name: "twitter:title", content: title }],
		["meta", { name: "twitter:description", content: description }],
	],
	metaChunk: true,
	srcDir: "./src",
	outDir: "./dist",
	themeConfig: {
		logo: { src: "/logo.svg", width: 24, height: 24 },
		nav: [{ text: "Setup", link: "/setup/" }],
		sidebar: [
			{
				items: [
					{ text: "Guide", link: "/guide/" },
					{ text: "Screenshots", link: "/screenshots/" },
					{ text: "Setup Instructions", link: "/setup/" },
					{ text: "Advanced Configuration", link: "/advanced-config/" },
					{ text: "Upgrading", link: "/upgrading/" },
					{ text: "Frequently Asked Questions", link: "/faq/" },
					{ text: "Certbot", link: "/certbot/" },
					{ text: "Third Party", link: "/third-party/" },
				],
			},
		],
		socialLinks: [{ icon: "github", link: "https://github.com/creimer808/nginx-proxy-manager" }],
		search: { provider: "local" },
		footer: {
			message: "Released under the MIT License. Unofficial fork of Nginx Proxy Manager.",
			copyright: "Copyright © 2017 Jamie Curnow; 2026 CyberSec.Cam and creimer808",
		},
	},
});
