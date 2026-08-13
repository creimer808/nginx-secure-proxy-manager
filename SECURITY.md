# Security Policy

## Supported versions

Only the latest stable **Nginx Secure Proxy Manager** release is supported with fork-specific security fixes.

| NSPM version | Upstream compatibility baseline | Supported |
| --- | --- | --- |
| 0.1.x | Nginx Proxy Manager 2.15.x | :white_check_mark: |
| Older NSPM releases | Any | :x: |

Images are published at `ghcr.io/creimer808/nginx-proxy-manager`. Pin an NSPM image digest in production. Protect GitHub release tags and keep GHCR numeric tags immutable; `latest` is intentionally mutable. An upstream NPM release notification indicates a compatibility update to review, not an NSPM image release.

## Reporting a vulnerability

**Do not open a public issue for a security vulnerability.** Use this repository's private vulnerability-reporting feature:

<https://github.com/creimer808/nginx-proxy-manager/security/advisories/new>

Include:

- NSPM application version and upstream compatibility version shown in the UI
- Image digest or tag
- Affected configuration and deployment type (without secrets)
- Reproduction steps, impact, and any proof of concept

Please redact credentials, JWTs, private keys, certificate contents, internal hostnames, and customer data. If the issue reproduces in an unmodified upstream Nginx Proxy Manager release, report it to the [upstream security process](https://github.com/NginxProxyManager/nginx-proxy-manager/security/advisories/new) as well.
