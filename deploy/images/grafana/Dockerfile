# Grafana OSS on UBI 9, from the official dl.grafana.com tarball; built by deploy\build-monitoring-images.bat.
FROM registry.access.redhat.com/ubi9:latest

# The YAML tag, e.g. 12.4.12 (a leading v is dropped).
ARG TAG

# The paths and console logging the official image uses; Grafana reads GF_* itself.
ENV PATH="/usr/share/grafana/bin:$PATH" \
    GF_PATHS_CONFIG="/etc/grafana/grafana.ini" \
    GF_PATHS_DATA="/var/lib/grafana" \
    GF_PATHS_HOME="/usr/share/grafana" \
    GF_PATHS_LOGS="/var/log/grafana" \
    GF_PATHS_PLUGINS="/var/lib/grafana/plugins" \
    GF_PATHS_PROVISIONING="/etc/grafana/provisioning" \
    GF_LOG_MODE="console"

# Download, check against the release's .sha256 (the build fails on a mismatch or an empty sums file), unpack, make the folders.
RUN set -eu; V="${TAG#v}"; F="grafana-${V}.linux-amd64.tar.gz"; cd /tmp; \
    curl -fsSL -o "$F" "https://dl.grafana.com/oss/release/$F"; \
    curl -fsSL -o "$F.sha256" "https://dl.grafana.com/oss/release/$F.sha256"; \
    echo "$(cat "$F.sha256")  $F" | sha256sum -c --strict; \
    mkdir -p "$GF_PATHS_HOME"; tar -xzf "$F" -C "$GF_PATHS_HOME" --strip-components=1; rm -f "$F" "$F.sha256"; \
    mkdir -p "$GF_PATHS_PROVISIONING/datasources" "$GF_PATHS_PROVISIONING/dashboards" "$GF_PATHS_PROVISIONING/plugins" \
             "$GF_PATHS_PROVISIONING/alerting" "$GF_PATHS_LOGS" "$GF_PATHS_PLUGINS" "$GF_PATHS_DATA/dashboards" "$GF_PATHS_HOME/.aws"; \
    cp "$GF_PATHS_HOME/conf/sample.ini" "$GF_PATHS_CONFIG"; cp "$GF_PATHS_HOME/conf/ldap.toml" /etc/grafana/ldap.toml; \
    chgrp -R 0 /etc/grafana "$GF_PATHS_DATA" "$GF_PATHS_LOGS" "$GF_PATHS_HOME/.aws"; \
    chmod -R g=u /etc/grafana "$GF_PATHS_DATA" "$GF_PATHS_LOGS" "$GF_PATHS_HOME/.aws"; \
    dnf clean all

# Any non-root UID in group 0 (OpenShift picks a random one).
USER 65534:0
WORKDIR /usr/share/grafana
EXPOSE 3000

# What the official image's run.sh runs (its cfg: paths and log mode are the GF_* above, so extra args still work).
ENTRYPOINT ["grafana", "server", "--homepath=/usr/share/grafana", "--config=/etc/grafana/grafana.ini", "--packaging=docker"]
