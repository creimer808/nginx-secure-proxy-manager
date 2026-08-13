# Security investigation

The top-level **Security** page turns locally generated Nginx telemetry into an investigation aid. It complements the lightweight aggregate dashboard; it is not an IDS, SIEM, or proof that a client is malicious or an application was compromised.

## What is recorded

A dedicated JSON Lines log is written for each proxy host when either:

- a built-in exploit rule matches; or
- the final response is `401`, `403`, `404`, `429`, or `5xx`.

Rule matches include a stable rule ID, category, action, and ruleset version. Status-only events are observations and have no exploit attribution. Exact attribution starts only after the upgraded Nginx configuration is active; older `403` responses cannot be attributed retroactively.

Detailed records include the full URI and query string, request method and protocol, interpreted client IP, immediate peer IP and port, status/upstream status, sizes and timing, TLS metadata, user agent, referrer, and Nginx error text. NSPM does **not** collect request bodies, cookies, `Authorization` values, or arbitrary request headers.

Full query strings can contain credentials or tokens. Security API responses use `private, no-store`, and the UI keeps free-text searches out of browser page history, but operators should still avoid placing secrets in URLs.

## Access control

Backend authorization is authoritative:

- Administrators can investigate all current hosts, deleted/orphaned event records, and allowlisted global/fallback HTTP logs.
- Other users require proxy-host `view`. Visibility `all` grants access to current active proxy hosts; owner-scoped visibility is filtered by current `owner_user_id`.
- Host/domain/owner snapshots preserve context but never grant access.
- Raw-log APIs accept host/global identifiers, log kind, and rotation—not filesystem paths.

## Retention and storage

Detailed database events default to **30 days**. Administrators can set an integer from **7 through 365 days** in **Security → Configuration**. Lowering retention takes effect during a later cleanup cycle.

Database retention does not remove raw log rotations, database backups, filesystem snapshots, or copied exports. Security logs rotate daily or at 50 MiB, retain 30 rotations, use delayed gzip compression, and are created with mode `0640`. Database and raw-log retention are intentionally separate.

The collector is bounded per cycle and pauses indexed ingestion when its configured high-water controls activate. Raw source logs remain the evidence source while backlog is deferred. Collector health is shown on the Security Overview; exact global counters are administrator-only.

### Collector configuration

| Environment variable | Default | Purpose |
| --- | ---: | --- |
| `SECURITY_EVENTS_ENABLED` | `true` | Set to `false` to stop detailed ingestion. Retained data remains subject to cleanup. |
| `SECURITY_EVENT_DATABASE_HIGH_WATER` | `1000000` | Conservative row-count pause threshold. |
| `SECURITY_EVENT_DATABASE_ESTIMATED_HIGH_WATER_BYTES` | `1073741824` | Database-storage pause threshold. NSPM measures table/index storage with the active driver and retains a conservative serialized-event estimate as fallback. |
| `SECURITY_EVENT_DATABASE_HEADROOM_BYTES` | `67108864` | Reserved estimated headroom before ingestion pauses. |
| `SECURITY_RAW_LOG_DISK_HIGH_WATER_PERCENT` | `90` | Filesystem-use percentage that pauses indexed ingestion and reports a warning. |

Invalid numeric values fall back to their defaults. Capacity depends on URI/message length, request volume, database engine, and storage hardware. Measure the intended deployment rather than assuming homelab traffic is always small.

Run a repeatable SQLite sizing probe from the repository root:

```bash
node backend/scripts/security-events-benchmark.js 10000
```

The script reports ingestion rate, common-query time, one retention-batch time, and database bytes per 10,000 synthetic events. It does not enforce timing thresholds.

## Client IP trust

The event shows both Nginx's interpreted client address and the immediate connection peer. The interpreted value is trustworthy only when `set_real_ip_from` ranges and ingress routing match the deployment. Review both values when investigating spoofing or proxy-boundary mistakes.

## Upgrade behavior

At startup, NSPM detects older generated proxy-host files that lack security logging. It renders replacements, prepares restrictive log files, preserves backups, runs `nginx -t`, and reloads only after validation. If validation or reload fails, the previous configurations are restored. Existing exploit protection remains enabled during this transition.

## Verification

The static Nginx contract tests run with the backend Node tests. The runtime attribution suite requires an explicitly selected candidate image:

```bash
SECURITY_NGINX_TEST_IMAGE=<candidate-image> \
  node --test docker/rootfs/etc/nginx/conf.d/include/security-rules.runtime.test.js
```

Do not use an unrelated or stale image when validating a release. MySQL and PostgreSQL migration/API checks should also be run in the repository's database CI matrix before release.
