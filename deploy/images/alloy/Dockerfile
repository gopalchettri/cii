# Alloy (ships the pods' logs to Loki) on UBI 9: the official linux-amd64 release, checked against its SHA256SUMS.
# Built by deploy\build-monitoring-images.bat (--build-arg TAG=<the tag in deploy_common.yaml>, e.g. v1.20.1).
FROM registry.access.redhat.com/ubi9:latest

ARG TAG

# Download the release, verify it (the build fails on a mismatch or a missing SHA256SUMS line), install /bin/alloy.
RUN set -eux; \
    : "${TAG:?pass --build-arg TAG}"; \
    url="https://github.com/grafana/alloy/releases/download/v${TAG#v}"; \
    dnf install -y --setopt=install_weak_deps=0 unzip; \
    cd /tmp; \
    curl -fsSLO "${url}/alloy-linux-amd64.zip"; \
    curl -fsSLO "${url}/SHA256SUMS"; \
    grep -x '[0-9a-f]\{64\}  alloy-linux-amd64\.zip' SHA256SUMS > alloy.sha256; \
    sha256sum -c alloy.sha256; \
    unzip -q alloy-linux-amd64.zip; \
    install -m 0755 alloy-linux-amd64 /bin/alloy; \
    rm -f alloy-linux-amd64 alloy-linux-amd64.zip SHA256SUMS alloy.sha256; \
    dnf remove -y unzip; \
    dnf clean all; \
    rm -rf /var/cache/dnf

# The config and storage folders the YAML mounts (and upstream's default storage), writable by group 0 (OpenShift's random UID).
RUN mkdir -p /etc/alloy /tmp/alloy /var/lib/alloy/data \
    && chown -R 65534:0 /etc/alloy /tmp/alloy /var/lib/alloy \
    && chmod -R g=u /etc/alloy /tmp/alloy /var/lib/alloy

USER 65534
EXPOSE 12345
ENTRYPOINT ["/bin/alloy"]
CMD ["run", "/etc/alloy/config.alloy", "--storage.path=/var/lib/alloy/data"]
