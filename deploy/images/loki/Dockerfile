# Loki (logs) on UBI 9: the official linux-amd64 release, checked against its SHA256SUMS.
# Built by deploy\build-monitoring-images.bat (--build-arg TAG=<the tag in deploy_common.yaml>, e.g. 3.7.8).
FROM registry.access.redhat.com/ubi9:latest

ARG TAG

# Download the release, verify it (the build fails on a mismatch or a missing SHA256SUMS line), install /usr/bin/loki.
RUN set -eux; \
    : "${TAG:?pass --build-arg TAG}"; \
    url="https://github.com/grafana/loki/releases/download/v${TAG#v}"; \
    dnf install -y --setopt=install_weak_deps=0 unzip; \
    cd /tmp; \
    curl -fsSLO "${url}/loki-linux-amd64.zip"; \
    curl -fsSLO "${url}/SHA256SUMS"; \
    grep -x '[0-9a-f]\{64\}  loki-linux-amd64\.zip' SHA256SUMS > loki.sha256; \
    sha256sum -c loki.sha256; \
    unzip -q loki-linux-amd64.zip; \
    install -m 0755 loki-linux-amd64 /usr/bin/loki; \
    rm -f loki-linux-amd64 loki-linux-amd64.zip SHA256SUMS loki.sha256; \
    dnf remove -y unzip; \
    dnf clean all; \
    rm -rf /var/cache/dnf

# The config and data folders the YAML mounts, writable by group 0 (OpenShift runs a random UID in group 0).
RUN mkdir -p /etc/loki /loki/rules /loki/rules-temp \
    && chown -R 65534:0 /etc/loki /loki \
    && chmod -R g=u /etc/loki /loki

USER 65534
EXPOSE 3100 9095
ENTRYPOINT ["/usr/bin/loki"]
