# ADR-001: Ship the monitoring files from observability/, not copies inside the configmap

**Status:** Accepted
**Date:** 2026-11-16
**Feature:** simplify-codebase
**Author:** 10x-Team (Architect + Staff Engineer)

## Context
`deploy/configmap.yaml` (about 10,000 lines) embeds byte-for-byte copies of 10 files in `observability/` (Prometheus,
rules, Alertmanager, Loki, Alloy, Grafana provisioning, the two dashboards, nginx). A test keeps the copies equal, so
every dashboard or alert edit is made twice (30 of 46 commits to the configmap also touched observability/).

## Decision
`deploy/configmap.yaml` keeps only the `tsg-config` settings. `deploy/kustomization.yaml` generates each monitoring
ConfigMap from its file with the same name and namespace (`disableNameSuffixHash: true`), applied with `oc apply -k
deploy`. Tests check the kustomization names every file, ConfigMap name and namespace.

## Alternatives Considered
| Alternative | Pros | Cons | Why Not |
|---|---|---|---|
| Keep the embedded copies | No procedure change | Every edit twice, 10,000 lines | The cost the owner wants gone |
| `oc create configmap --from-file` lines in the guide | No new file | Seven commands to keep in step | One declarative file is simpler |

## Consequences
### Positive
- About 10,000 fewer lines; one edit per dashboard or rule change.
### Negative
- The release steps change from `oc apply -f deploy/configmap.yaml` to `oc apply -k deploy`.
### Risks
- A ConfigMap name or namespace drifts: the test compares them with the deployments' volumes.

## Dependencies
- `oc` with kustomize (built in since OpenShift 4.x).
