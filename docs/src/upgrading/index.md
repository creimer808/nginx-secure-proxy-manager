---
outline: deep
---

# Upgrading

1. Review the [NSPM releases](https://github.com/creimer808/nginx-proxy-manager/releases) and any matching upstream compatibility notes.
2. Update the pinned NSPM image tag or digest in `docker-compose.yml`.
3. Pull and recreate the service:

```bash
docker compose pull
docker compose up -d
```

A pinned tag does not change when you run `docker compose pull`; update the tag or digest first. NSPM performs required database migrations at startup. Review upstream notes only as compatibility references, because an upstream release does not automatically create an NSPM release.
