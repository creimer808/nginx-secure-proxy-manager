---
outline: deep
---

# Nginx Secure Proxy Manager guide

Nginx Secure Proxy Manager (NSPM) is a security-focused, unofficial fork of [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager). It preserves the approachable proxy-management core and adds security and traffic visibility.

| Version | Current value |
| --- | --- |
| NSPM application | `0.1.0` |
| Upstream NPM compatibility baseline | `2.15.1` |

> NSPM is independently maintained by [CyberSec.Cam](https://www.cybersec.cam) / [creimer808](https://github.com/creimer808). It is not affiliated with or endorsed by NGINX, Inc. or the official Nginx Proxy Manager project.

## Features

- Proxy hosts, redirects, streams, certificates, access lists, users, and audit logging inherited from Nginx Proxy Manager.
- Security and traffic dashboard for reviewing local proxy activity.
- Let's Encrypt and custom certificate support.
- Advanced Nginx configuration for experienced operators.

## Quick setup

```yaml
services:
  app:
    image: ghcr.io/creimer808/nginx-proxy-manager:0.1.0
    restart: unless-stopped
    ports:
      - "80:80"
      - "81:81"
      - "443:443"
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
```

Start with `docker compose up -d`, then open [http://127.0.0.1:81](http://127.0.0.1:81) to complete setup. Pin an NSPM version tag rather than using `latest` in production.

## Upstream relationship

NSPM follows stable upstream releases, not `develop`. An upstream update notice is a compatibility signal rather than an automatic NSPM upgrade. See [UPSTREAM.md](https://github.com/creimer808/nginx-proxy-manager/blob/custom/UPSTREAM.md) for the synchronization process.

## Support

Report NSPM issues at [github.com/creimer808/nginx-proxy-manager/issues](https://github.com/creimer808/nginx-proxy-manager/issues), including both versions shown in the UI. If a problem reproduces on an unmodified upstream Nginx Proxy Manager image, report it to the upstream project.
