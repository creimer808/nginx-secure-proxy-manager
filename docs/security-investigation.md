# Security investigation

The top-level **Security** page turns locally generated Nginx telemetry into an investigation aid. It complements the lightweight aggregate dashboard; it is not an IDS, SIEM, or proof that a client is malicious or an application was compromised.

> **v0.1.2 collected no data.** In v0.1.2 the Security page shipped functionally inert. Nginx never received the security logging directive — the startup upgrade's commit gate included a reload that lost a startup race and rolled every host back — and the collector spent its whole per-cycle budget re-hashing existing log archives, so it could never advance a cursor. Both failures were silent: startup logs looked healthy and the page showed an empty but "Available" collector.
>
> v0.1.3 fixes both. There is nothing to recover: no telemetry from the v0.1.2 period was ever written, and no backfill is performed. Collection begins from the point v0.1.3 starts.

## What is recorded

A dedicated JSON Lines log is written for each proxy host when either:

- a built-in rule matches; or
- the final response is `401`, `403`, `404`, `429`, or `5xx`.

Rule matches include a stable rule ID, category, action, and ruleset version. Status-only events are observations and have no rule attribution. Exact attribution starts only after the upgraded Nginx configuration is active; older `403` responses cannot be attributed retroactively.

### Detection and blocking are separate

Every host is told what matched, whether or not it blocks. `rule_action` records what actually happened to the request:

| Action | Meaning | Severity |
| --- | --- | --- |
| `block` | An upstream-inherited signature matched on a host with **Block Common Exploits** enabled. The request received a `403`. | `high` |
| `detect` | A match that changed nothing about the response — either a detect-only rule, or an inherited signature on a host that has blocking switched off. | `medium` |

Earlier releases gated attribution on the blocking switch, so a host with **Block Common Exploits** off recorded no rule matches at all. Enabling blocking is no longer a prerequisite for seeing what is being attempted, and turning it on or off does not change which rules are evaluated — only whether the inherited ones return `403`.

The rule catalog has two groups:

- **Inherited signatures** (`sql.*`, `file.*`, `common.*`, `php.*`, `lfi.*`, `joomla.*`, `spam.*`, `ua.*`) come from upstream's `block-exploits.conf`. These are the only rules that can block, and only when the host opts in.
- **Detect-only rules** (`path.*`, `inject.*`, `scanner.*`) never change a response. Each matches something that is legitimate somewhere — `/actuator` on a Spring host, `/cgi-bin` on genuinely old software — so they are evidence to review, not grounds to break a working site.

Where a request matches both groups, the inherited signature wins, so blocking decisions land exactly where they did before the detect-only rules existed.

### Operational records are not security findings

Nginx error-log lines are collected as `nginx_error` events. They are operational observations: failed TLS handshakes, upstream timeouts, clients that hung up mid-request. One flapping upstream produces thousands, and they carry no client IP, status, method, or rule.

They are therefore excluded from the security totals, the timeline, and every top-N list, and from event search unless `include_operational=true` is set. Nothing operational is recorded above `medium` severity. The raw error logs remain browsable in full.

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

At startup, NSPM detects older generated proxy-host files that lack security logging. Each host is rendered, staged, validated with `nginx -t`, and committed on its own, so a single host that cannot be validated — an expired certificate file, an unusual `advanced_config` — is restored and skipped without affecting the others.

A successful `nginx -t` is the commit point. Reloading is a delivery step, not a validation step: the backend and Nginx start concurrently under s6 with no readiness ordering between them, so when Nginx is not yet running the reload is skipped and the new files are read when it starts.

The result is recorded and shown in **Security → Configuration**: hosts upgraded, hosts skipped, whether the reload was deferred, and the last failure reason. If logging is not active, that panel says so without requiring container logs.

## Coverage outside proxy hosts

Requests that never reach a proxy host — unknown `Host` headers, raw-IP hits, background scanning — are recorded in `/data/logs/fallback_security.log` by the default and fallback servers. Redirection hosts, dead hosts, and a configured default site write there too, because those have their own id spaces and cannot be attributed to a `proxy_host_id`.

Fallback records carry no proxy host id. The existing visibility guard requires a non-null `proxy_host_id` for non-administrators, so these events, and the raw fallback log, are administrator-only.

Existing redirection-host and dead-host configurations are regenerated when they are next saved; the startup upgrade covers proxy hosts only.

## Verification

The static Nginx contract tests run with the backend Node tests. The runtime attribution suite requires an explicitly selected candidate image, and runs in CI against the built candidate before anything is published:

```bash
SECURITY_NGINX_TEST_IMAGE=<candidate-image> \
  node --test backend/lib/security-rules.runtime.test.js
```

It mounts the repository's `nginx.conf`, `security-rules.conf`, `block-exploits.conf`, and `log-proxy.conf` over the image, so it tests the working tree against that image's surrounding configuration. It asserts one case per rule, that detect-only rules leave the response untouched, that ordinary traffic produces no record at all, and that an inherited signature still wins over an overlapping detect-only rule.

Do not use an unrelated or stale image when validating a release. MySQL and PostgreSQL migration/API checks should also be run in the repository's database CI matrix before release.
