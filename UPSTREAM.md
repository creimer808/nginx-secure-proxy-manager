# Upstream synchronization

Nginx Secure Proxy Manager (NSPM) is an unofficial fork of [Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager). We track **stable upstream releases**, not the upstream `develop` branch, to keep the production baseline reviewable and supportable.

## Version relationship

Each NSPM release has two independent versions:

- **NSPM application version**: the fork's semantic release, for example `0.1.2`.
- **Upstream compatibility baseline**: the stable Nginx Proxy Manager release incorporated by that fork release, for example `2.15.1`.

The sources are deliberately separate:

- `.app-version` is the NSPM release version.
- `.version` is the upstream compatibility baseline.
- `backend/package.json` and `frontend/package.json` mirror both values for runtime metadata.

Do not use an upstream `v2.x` tag as an NSPM release tag. NSPM releases use tags such as `v0.1.2`.

## Sync procedure

1. Fetch the `upstream` remote and identify the next stable upstream release tag.
2. Review its release notes, migrations, dependency changes, security impact, and conflict surface against NSPM changes.
3. Merge or rebase the stable tag into the NSPM integration branch. Do not merge `upstream/develop` into the stable release branch.
4. Resolve conflicts without removing NSPM security features or upstream license notices.
5. Update `.version`, `backend/package.json#upstreamVersion`, and `frontend/package.json#upstreamVersion` to the incorporated upstream release.
6. Keep `.app-version` and both package `version` fields at the next intended NSPM release version. Update the Docker base-image index digests in `docker/Dockerfile` only after reviewing the upstream image change.
7. Run backend tests/schema validation, frontend tests/build, documentation build, and an upgrade test against supported data stores.
8. Confirm the health endpoint preserves the legacy `version` object as the upstream version while reporting `app_version` and `upstream_version` explicitly.
9. Create the custom release tag (`v<app-version>`) only after review and verification. Protect release tags against recreation. CI refuses to overwrite an existing numeric image tag and publishes the NSPM version tag, `upstream-<baseline>`, `latest`, and a commit SHA tag from that tag.

## Conflict and security policy

Prioritize security fixes and upstream data migrations. If a conflict affects authorization, certificate handling, log privacy, or upgrade safety, document the decision in the pull request and add regression coverage before release. Do not silently drop upstream fixes just to preserve fork-specific UI behavior.

Upstream release checks in the UI are compatibility signals only: an available NPM release does not mean an NSPM release exists. Review and integrate it through this process.
