# kube-state-metrics on UBI 9, built from its source (the project publishes no binary); built by deploy\build-monitoring-images.bat.
# The project publishes no checksum for its source archive: SRC_SHA256 is the sha256 of the v2.20.0 archive,
# measured 2026-10-24. A new TAG needs its own SRC_SHA256 (sha256sum of the new archive), or the build fails.
ARG TAG=v2.20.0
ARG SRC_SHA256=d629314a4b8eaa64ef7e72ff87e0e1d2f62825b33e0cdfa37f642bc174d670f7

# Stage 1: download the source for TAG, check its sha256, build a static binary with the Makefile's version flags.
FROM registry.access.redhat.com/ubi9/go-toolset:latest AS build
ARG TAG
ARG SRC_SHA256
ENV CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=auto
RUN curl -fsSL -o src.tar.gz "https://github.com/kubernetes/kube-state-metrics/archive/refs/tags/${TAG}.tar.gz" \
 && echo "${SRC_SHA256}  src.tar.gz" | sha256sum -c - \
 && mkdir ksm && tar -xzf src.tar.gz -C ksm --strip-components=1 && rm src.tar.gz && cd ksm \
 && go build -o /tmp/kube-state-metrics -ldflags "-s -w \
      -X github.com/prometheus/common/version.Version=${TAG} \
      -X github.com/prometheus/common/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ) \
      -X k8s.io/kube-state-metrics/v2/pkg/app.ClientGoVersion=$(go list -m -f '{{.Version}}' k8s.io/client-go)" .

# Stage 2: the binary alone on UBI 9, at the path and with the entrypoint of the upstream image.
FROM registry.access.redhat.com/ubi9:latest
COPY --from=build /tmp/kube-state-metrics /kube-state-metrics
USER 65534
EXPOSE 8080 8081
ENTRYPOINT ["/kube-state-metrics", "--port=8080", "--telemetry-port=8081"]
