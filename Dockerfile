# TSG v2 image. The API, every worker, beat and Flower run from this one image; the command in
# deploy/deploy_threatgen.yaml and deploy_common.yaml picks the role.
# Built, checked and pushed by deploy\build-image.bat.
#
# UBI 9: the cluster pulls only Red Hat images and our own. Python 3.12 comes from the UBI repos, ODBC
# Driver 17 (the UAT connection string names it) from Microsoft's RHEL 9 repo.
FROM registry.access.redhat.com/ubi9:latest

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PYTHONPATH=/app
# One BLAS thread per process: numpy started one per node core, so vector searches used 13-17x the CPU
# of a 250m limit.
ENV OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1

# Python 3.12 as "python" and "pip", and Microsoft's ODBC Driver 17 (unixODBC from UBI AppStream).
RUN dnf install -y python3.12 python3.12-pip \
 && ln -sf /usr/bin/python3.12 /usr/local/bin/python \
 && ln -sf /usr/bin/pip3.12 /usr/local/bin/pip \
 && curl -fsSL -o /etc/yum.repos.d/mssql-release.repo https://packages.microsoft.com/config/rhel/9/prod.repo \
 && ACCEPT_EULA=Y dnf install -y msodbcsql17 \
 && dnf clean all \
 && rm -rf /var/cache/dnf

WORKDIR /app
# The dependencies alone, at the versions the tests passed on (requirements.txt): their own layer, so a code
# change does not reinstall them. The app itself is not installed as a package: it runs from /app
# (PYTHONPATH), where its sources are replaced by bytecode below. No `local` extra: UAT and production use
# the proxy's reranker, so no torch and no model files. pip puts uvicorn and celery in /usr/local/bin.
COPY pyproject.toml requirements.txt ./
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml', 'rb'))['project']['dependencies']))" \
        > /tmp/dependencies.txt \
 && pip install -r /tmp/dependencies.txt -c requirements.txt \
 && rm /tmp/dependencies.txt

COPY app ./app
# Bytecode only, as v1: a deterrent (bytecode can be decompiled), not a security boundary.
RUN python -m compileall -b -q app \
 && find app -name '*.py' -delete \
 && find app -name '__pycache__' -type d -prune -exec rm -rf {} +

# OpenShift runs the container as a random user in group 0: /app belongs to group 0 with the owner's rights
# (beat writes its schedule to an emptyDir, never here). 10001 is the user everywhere else.
RUN useradd -u 10001 -g 0 -M -d /app tsg && chown -R 10001:0 /app && chmod -R g=u /app
USER 10001

EXPOSE 8000 9100
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-access-log", \
     "--timeout-graceful-shutdown", "30"]
