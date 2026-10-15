# TSG v2 image. The API, every worker, beat and Flower run from this one image; the command in
# deploy/app.yaml (and deploy/observability.yaml for Flower) picks the role. Build and push with
# deploy/build-image.ps1, which tags it with the git commit.
#
# Bookworm by name: Microsoft's ODBC Driver 17 package below is published for Debian 12, and the UAT
# connection string names Driver 17 (as v1's does). A plain python:3.12-slim follows Debian's newest release.
FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl gnupg ca-certificates \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
        | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
        > /etc/apt/sources.list.d/mssql-release.list \
 && apt-get update \
 && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql17 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# The dependencies alone, at the versions the tests passed on (requirements.txt): their own layer, so a code
# change does not reinstall them. The app itself is not installed as a package: it runs from /app
# (PYTHONPATH), where its sources are replaced by bytecode below. No `local` extra: UAT and production use
# the proxy's reranker, so no torch and no model files.
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
