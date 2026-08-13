---
outline: deep
---

# FAQ

## Do I have to use Docker?

Yes. Containers let NSPM ship the tested Nginx and application runtime together.

## Can I run it on a Raspberry Pi?

Yes, on supported `arm64` devices. See the [NSPM GHCR package](https://github.com/creimer808/nginx-proxy-manager/pkgs/container/nginx-proxy-manager) for published architectures. `armv7` is not supported; request additional architectures through an [NSPM feature request](https://github.com/creimer808/nginx-proxy-manager/issues/new?template=feature_request.md).

## I can't get my service to proxy properly

Open an NSPM issue with both versions shown in the UI and redacted configuration details. The [upstream Reddit community](https://www.reddit.com/r/nginxproxymanager/) may help with generic Nginx Proxy Manager behavior, but it does not support NSPM-specific changes.

## When adding username and password access control to a proxy host, I can no longer log in to the app

An Access Control List (ACL) sends credentials in the `Authorization` header. If the proxied application also uses that header, browsers and many applications cannot safely carry two independent values. Remove one authentication layer or configure the application to use another supported authentication mechanism.
