# redis_exporter on UBI 9, from the official linux-amd64 release; built by deploy\build-monitoring-images.bat.
FROM registry.access.redhat.com/ubi9:latest
# The deploy_common.yaml tag, e.g. v1.93.0.
ARG TAG

# Download, check against the release's sha256sums.txt, install /redis_exporter.
RUN set -eu; V="${TAG:?pass --build-arg TAG}"; V="${V#v}"; F="redis_exporter-v${V}.linux-amd64.tar.gz"; \
    U="https://github.com/oliver006/redis_exporter/releases/download/v${V}"; D="$(mktemp -d)"; cd "$D"; \
    curl -fsSL -o "$F" "$U/$F"; curl -fsSL -o sums.txt "$U/sha256sums.txt"; \
    grep "  ${F}\$" sums.txt > sum.txt; sha256sum -c sum.txt; tar -xzf "$F"; \
    install -m 0755 "redis_exporter-v${V}.linux-amd64/redis_exporter" /redis_exporter; \
    cd /; rm -rf "$D"

# Reads everything from its environment (REDIS_ADDR ...); writes nothing.
USER 65534
EXPOSE 9121
ENTRYPOINT ["/redis_exporter"]
