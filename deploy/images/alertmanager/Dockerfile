# Alertmanager on UBI 9, from the official linux-amd64 release; built by deploy\build-monitoring-images.bat.
FROM registry.access.redhat.com/ubi9:latest
# The deploy_common.yaml tag, e.g. v0.34.1.
ARG TAG

# Download, check against the release's sha256sums.txt, install /bin/alertmanager and /bin/amtool.
RUN set -eu; V="${TAG:?pass --build-arg TAG}"; V="${V#v}"; F="alertmanager-${V}.linux-amd64.tar.gz"; \
    U="https://github.com/prometheus/alertmanager/releases/download/v${V}"; D="$(mktemp -d)"; cd "$D"; \
    curl -fsSL -o "$F" "$U/$F"; curl -fsSL -o sums.txt "$U/sha256sums.txt"; \
    grep "  ${F}\$" sums.txt > sum.txt; sha256sum -c sum.txt; tar -xzf "$F"; \
    install -m 0755 "alertmanager-${V}.linux-amd64/alertmanager" "alertmanager-${V}.linux-amd64/amtool" /bin/; \
    cd /; rm -rf "$D"; \
    mkdir -p /alertmanager; chgrp -R 0 /alertmanager; chmod -R g=u /alertmanager

# The silences folder (the YAML mounts an emptyDir here), writable by OpenShift's random UID in group 0.
WORKDIR /alertmanager
USER 65534
EXPOSE 9093
ENTRYPOINT ["/bin/alertmanager"]
