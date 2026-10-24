# Prometheus on UBI 9, from the official linux-amd64 release; built by deploy\build-monitoring-images.bat.
FROM registry.access.redhat.com/ubi9:latest
# The deploy_common.yaml tag, e.g. v3.15.0.
ARG TAG

# Download, check against the release's sha256sums.txt, install /bin/prometheus and /bin/promtool.
RUN set -eu; V="${TAG:?pass --build-arg TAG}"; V="${V#v}"; F="prometheus-${V}.linux-amd64.tar.gz"; \
    U="https://github.com/prometheus/prometheus/releases/download/v${V}"; D="$(mktemp -d)"; cd "$D"; \
    curl -fsSL -o "$F" "$U/$F"; curl -fsSL -o sums.txt "$U/sha256sums.txt"; \
    grep "  ${F}\$" sums.txt > sum.txt; sha256sum -c sum.txt; tar -xzf "$F"; \
    install -m 0755 "prometheus-${V}.linux-amd64/prometheus" "prometheus-${V}.linux-amd64/promtool" /bin/; \
    cd /; rm -rf "$D"; \
    mkdir -p /prometheus; chgrp -R 0 /prometheus; chmod -R g=u /prometheus

# The data folder (the YAML mounts a volume here), writable by OpenShift's random UID in group 0.
WORKDIR /prometheus
USER 65534
EXPOSE 9090
ENTRYPOINT ["/bin/prometheus"]
