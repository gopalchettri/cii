# nginx (the monitoring proxy in ai-threatgen) on Red Hat's UBI 9 nginx 1.24 image; built by deploy\build-monitoring-images.bat.
# The base tag is pinned: its nginx is 1.24.0, the deploy_common.yaml tag. The script checks that the image prints
# that version, so a new base tag with another nginx fails until the YAML tag is changed to match.
FROM registry.access.redhat.com/ubi9/nginx-124:9.8-1791835842
# The deploy_common.yaml tag, e.g. 1.24.0 (the script passes it; the base tag above decides the version).
ARG TAG

# Its config is ConfigMap monitoring-proxy (deploy\configmap.yaml), passed with -c in deploy_common.yaml; without
# arguments it runs the image's own config in the foreground. Any non-root user (OpenShift picks a random one).
USER 1001
EXPOSE 8080
ENTRYPOINT ["/usr/sbin/nginx"]
CMD ["-e", "stderr", "-g", "daemon off;"]
