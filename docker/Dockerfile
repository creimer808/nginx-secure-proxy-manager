# This is a Dockerfile intended to be built using `docker buildx`
# for multi-arch support. Building with `docker build` may have unexpected results.

# This file assumes that the frontend has been built using ./scripts/frontend-build

# Update these reviewed index digests through the stable upstream-sync process in UPSTREAM.md.
ARG BASE_IMAGE=nginxproxymanager/nginx-full:certbot-node@sha256:f5e8c2a11d4f91807b9df9f823f6ec90b40366717fc0892fb342866a8eadb240
FROM nginxproxymanager/testca@sha256:3e23c78c64789b8e95126589dd502127e57bbad6091a5a88a67ffb87a16f6b6a AS testca
FROM $BASE_IMAGE

ARG BASE_IMAGE
ARG TARGETPLATFORM
ARG BUILD_VERSION
ARG BUILD_COMMIT
ARG BUILD_DATE
ARG UPSTREAM_VERSION

# See: https://github.com/just-containers/s6-overlay/blob/master/README.md
ENV SUPPRESS_NO_CONFIG_WARNING=1 \
	S6_BEHAVIOUR_IF_STAGE2_FAILS=1 \
	S6_CMD_WAIT_FOR_SERVICES_MAXTIME=0 \
	S6_FIX_ATTRS_HIDDEN=1 \
	S6_KILL_FINISH_MAXTIME=10000 \
	S6_VERBOSITY=1 \
	NODE_ENV=production \
	NPM_BUILD_VERSION="${BUILD_VERSION}" \
	NPM_BUILD_COMMIT="${BUILD_COMMIT}" \
	NPM_BUILD_DATE="${BUILD_DATE}" \
	NSPM_UPSTREAM_VERSION="${UPSTREAM_VERSION}" \
	NODE_OPTIONS="--openssl-legacy-provider"

RUN echo "fs.file-max = 65535" > /etc/sysctl.conf \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends jq logrotate \
	&& apt-get clean \
	&& rm -rf /var/lib/apt/lists/*

# s6 overlay
COPY docker/scripts/install-s6 /tmp/install-s6
RUN /tmp/install-s6 "${TARGETPLATFORM}" && rm -f /tmp/install-s6

EXPOSE 80 81 443

COPY backend       /app
COPY frontend/dist /app/frontend
COPY docker/rootfs /

# Copy test CA cert for use in container and add to trusted certs from a self-signed CA
COPY --from=testca /home/step/certs/root_ca.crt /etc/ssl/certs/NginxProxyManager.crt
WORKDIR /etc/ssl/certs
RUN ln -s NginxProxyManager.crt 1d0e3f10.0 && update-ca-certificates

WORKDIR /app
RUN yarn install \
	&& yarn cache clean

# Remove frontend service not required for prod, dev nginx config as well
RUN rm -rf /etc/s6-overlay/s6-rc.d/user/contents.d/frontend /etc/nginx/conf.d/dev.conf \
	&& chmod 644 /etc/logrotate.d/nginx-proxy-manager

VOLUME [ "/data" ]
ENTRYPOINT [ "/init" ]

LABEL org.label-schema.schema-version="1.0" \
	org.label-schema.license="MIT" \
	org.label-schema.name="nginx-secure-proxy-manager" \
	org.label-schema.description="Security-focused Nginx Proxy Manager fork with traffic visibility" \
	org.label-schema.url="https://github.com/creimer808/nginx-proxy-manager" \
	org.label-schema.vcs-url="https://github.com/creimer808/nginx-proxy-manager.git" \
	org.label-schema.cmd="docker run --rm -ti ghcr.io/creimer808/nginx-proxy-manager:latest" \
	org.opencontainers.image.version="${BUILD_VERSION}" \
	org.opencontainers.image.revision="${BUILD_COMMIT}" \
	org.opencontainers.image.created="${BUILD_DATE}" \
	org.opencontainers.image.source="https://github.com/creimer808/nginx-proxy-manager" \
	org.opencontainers.image.base.name="${BASE_IMAGE}" \
	io.cybersec-cam.nspm.upstream-version="${UPSTREAM_VERSION}"
