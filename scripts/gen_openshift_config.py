"""TSG's settings for OpenShift, made from one tested env file (.env.uat): the ConfigMap tsg-config (plain
settings) and the Secret tsg-secrets (keys, passwords and connection strings) that every app pod reads with
envFrom, in both projects (ai-threatgen and ai-remediation get the same two: they cannot differ).

    .venv\\Scripts\\python scripts\\gen_openshift_config.py .env.uat | oc -n ai-threatgen apply -f -
    .venv\\Scripts\\python scripts\\gen_openshift_config.py .env.uat --gate [--monitoring]
    .venv\\Scripts\\python scripts\\gen_openshift_config.py .env.uat --fingerprint

Only the settings the app reads are copied, under the names it reads them by (app/core/config.py). Left out,
by name on stderr: CII_LOG_DIR (pods log to stdout, where Alloy collects them), the monitoring lines
(deploy/observability.ps1 reads them from the same file) and any line the app does not read. No value is
ever printed: the YAML goes straight to `oc apply`, the Secret's values base64-encoded as `data`.

--gate builds the app's settings exactly as a pod would, from these two maps alone (no .env file, nothing
from this computer's environment), so a setting that would stop every pod at start-up (a missing required
line, a "*" CORS origin, a short admin key, no evidence threshold) is found before anything is changed. It
also checks that each store the settings name is an address the egress rules (deploy/networkpolicy.yaml,
deploy/networkpolicy.ai-remediation.yaml) let the pods reach, and that each AI gateway is https on port 443,
pinned (hostAliases) and on NO_PROXY and no_proxy in every app pod (deploy/deploy.yaml,
deploy/deploy.ai-remediation.yaml): through the corporate proxy it times out (UAT, 2026-10-21). --monitoring
adds what deploy/observability.ps1 needs. Prints GATE OK, or each problem by setting name and exits 1.

--fingerprint prints a short digest of both maps: deploy/deploy-uat.ps1 puts it on every app pod, so the pods
roll when a setting changed and stay as they are when none did."""

import argparse
import base64
import hashlib
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import yaml
from dotenv import dotenv_values
from pydantic import SecretStr, ValidationError

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))  # `app` from this checkout, never another installed copy

from app.core.config import Settings  # noqa: E402
from app.core.constants import LITELLM_MODEL_PREFIX  # noqa: E402

#: The egress rules of each project the app's pods run in.
NETWORK_RULES = (
    REPO / "deploy" / "networkpolicy.yaml",
    REPO / "deploy" / "networkpolicy.ai-remediation.yaml",
)
#: The app's pods, in each project.
APP_MANIFESTS = (REPO / "deploy" / "deploy.yaml", REPO / "deploy" / "deploy.ai-remediation.yaml")
#: Each AI model and the base URL its calls go to.
GATEWAYS = (
    ("chat_model", "chat_base_url"),
    ("chat_fallback_model", "chat_base_url"),
    ("embedding_model", "embedding_base_url"),
    ("rerank_model", "rerank_base_url"),
)
CONFIG_MAP, SECRET = "tsg-config", "tsg-secrets"  # the names deploy/*.yaml read with envFrom
LABELS = {"app.kubernetes.io/part-of": "tsg"}
#: Connection strings carry their password: they go to the Secret, with the keys.
CONNECTIONS = {"db_dsn", "mongo_url", "redis_url", "redis_celery_broker_url"}
#: Read by the app on a laptop only.
LAPTOP_ONLY = {"CII_LOG_DIR"}
#: The settings that name a store the pods must reach.
STORES = ("CII_REDIS_URL", "CII_REDIS_CELERY_BROKER_URL", "CII_MONGO_URL", "CII_DB_DSN")
DEFAULT_PORTS = {"redis": "6379", "mongodb": "27017", "mssql+pyodbc": "1433"}
MIN_GRAFANA_PASSWORD = 16  # deploy/observability.ps1 refuses a shorter one


def env_name(field: str) -> str:
    """The environment name a setting is read from: the owner's own name (CONTROL_CANDIDATES), else
    CII_<FIELD>."""
    alias = Settings.model_fields[field].validation_alias
    return alias if isinstance(alias, str) else f"CII_{field.upper()}"


def read_env(path: Path) -> dict[str, str]:
    """KEY=value lines as the app reads them (python-dotenv); a key with no '=' is skipped."""
    return {key: value for key, value in dotenv_values(path).items() if value is not None}


def split_settings(values: dict[str, str]) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """(ConfigMap data, Secret data, the names left out). A setting is secret when the app holds it as a
    SecretStr, or when it is a connection string."""
    fields = {env_name(field): field for field in Settings.model_fields}
    secret_fields = CONNECTIONS | {
        field for field, info in Settings.model_fields.items() if info.annotation is SecretStr
    }
    config: dict[str, str] = {}
    secret: dict[str, str] = {}
    left_out = []
    for key, value in values.items():
        field = fields.get(key.upper())
        if field is None or key.upper() in LAPTOP_ONLY:
            left_out.append(key)
        else:
            (secret if field in secret_fields else config)[key.upper()] = value
    return config, secret, sorted(left_out)


def reachable(rules: Path) -> set[tuple[str, str]]:
    """Every (IP, port) a NetworkPolicy file's egress rules let the pods reach (ipBlock rules only)."""
    found = set()
    for policy in yaml.safe_load_all(rules.read_text(encoding="utf-8")):
        for rule in (policy or {}).get("spec", {}).get("egress", []):
            hosts = [peer["ipBlock"]["cidr"].removesuffix("/32") for peer in rule["to"] if "ipBlock" in peer]
            found |= {(host, str(port["port"])) for host in hosts for port in rule.get("ports", [])}
    return found


def manifests(config: dict[str, str], secret: dict[str, str]) -> str:
    """The ConfigMap and the Secret as YAML, plain ASCII (any other character is escaped)."""
    encoded = {key: base64.b64encode(value.encode()).decode() for key, value in secret.items()}
    documents = [
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": CONFIG_MAP, "labels": LABELS},
            "data": config,
        },
        {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": SECRET, "labels": LABELS},
            "type": "Opaque",
            "data": encoded,
        },
    ]
    return yaml.safe_dump_all(documents, sort_keys=False)


def settings_problems(environment: dict[str, str]) -> list[str]:
    """What stops the app's settings from loading in a pod given exactly `environment`, or would cut the pods
    off the AI gateway. Messages name the setting, never its value (pydantic's input is left out)."""
    saved = dict(os.environ)
    os.environ.clear()
    os.environ.update(environment)
    try:
        settings = Settings(_env_file=None)  # type: ignore[call-arg]
    except ValidationError as exc:
        return [_problem(error["loc"], error["msg"]) for error in exc.errors(include_input=False)]
    finally:
        os.environ.clear()
        os.environ.update(saved)
    if not settings.ai_bypass_proxy:  # owner 2026-10-16 (G264): as on the UAT Windows server
        return [
            f"{env_name('ai_bypass_proxy')}: must be true here: the pods call the AI gateway directly "
            "(hostAliases); only the outside calls, the intel feeds, go through the proxy (HTTPS_PROXY)"
        ]
    return []


def _problem(location: tuple[int | str, ...], message: str) -> str:
    where = str(location[0]) if location else "settings"
    return f"{env_name(where) if where in Settings.model_fields else where}: {message}"


def store_problems(environment: dict[str, str], rule_files: tuple[Path, ...] = NETWORK_RULES) -> list[str]:
    """Each store address in the settings that a project's egress rules do not allow: its pods could not
    reach it."""
    problems = []
    for rules in rule_files:
        allowed = reachable(rules)
        for key in STORES:
            for address in addresses(environment.get(key, "")):
                if address not in allowed:
                    where = rules.relative_to(REPO).as_posix()
                    problems.append(
                        f"{key}: {':'.join(address)} is not an address {where} lets the pods reach"
                    )
    return problems


def gateway_problems(environment: dict[str, str], app_files: tuple[Path, ...] = APP_MANIFESTS) -> list[str]:
    """Each LiteLLM gateway (litellm_proxy/ models) the app pods could not call directly: not https on 443
    (the only port the egress rules open to it), or in a pod without its host pinned (hostAliases) or on
    NO_PROXY and no_proxy, whose calls then go to the corporate proxy, which cannot reach it."""
    gateways: dict[str, str] = {}
    for model, url in GATEWAYS:
        address = environment.get(env_name(url), "")
        if environment.get(env_name(model), "").startswith(LITELLM_MODEL_PREFIX) and address:
            gateways.setdefault(address, env_name(url))
    problems = []
    for address, key in gateways.items():
        parts = urlsplit(address if "//" in address else f"https://{address}")
        if parts.scheme != "https" or parts.port not in (None, 443):
            problems.append(
                f"{key}: the AI gateway must be https on port 443, the port the egress rules open"
            )
        for path in app_files:
            problems += [f"{key}: {parts.hostname} {gap}" for gap in _gateway_gaps(str(parts.hostname), path)]
    return problems


def _gateway_gaps(host: str, path: Path) -> list[str]:
    """What a manifest's app pods lack to call `host` directly, one line per pod and gap."""
    where = path.relative_to(REPO).as_posix()
    gaps = []
    for item in yaml.safe_load_all(path.read_text(encoding="utf-8")):
        if (item or {}).get("kind") != "Deployment":
            continue
        name, pod = item["metadata"]["name"], item["spec"]["template"]["spec"]
        if host not in {name for alias in pod.get("hostAliases", []) for name in alias["hostnames"]}:
            gaps.append(f"is not pinned (hostAliases) in {where} {name}")
        for container in pod["containers"]:
            env = {variable["name"]: variable.get("value", "") for variable in container.get("env", [])}
            for variable in ("NO_PROXY", "no_proxy"):
                entries = [entry.strip() for entry in env.get(variable, "").split(",")]
                if not any(host == e or (e.startswith(".") and host.endswith(e)) for e in entries):
                    gaps.append(f"is not on {variable} in {where} {name}: its AI calls would go to the proxy")
    return gaps


def addresses(url: str) -> list[tuple[str, str]]:
    """Every host and port a connection string names (MongoDB may list several), without its password."""
    if not url:
        return []
    parts = urlsplit(url)
    default = DEFAULT_PORTS.get(parts.scheme, "")
    found = []
    for host in parts.netloc.rpartition("@")[2].split(","):
        name, _, port = host.partition(":")
        found.append((name, port or default))
    return found


def monitoring_problems(values: dict[str, str]) -> list[str]:
    """No GRAFANA_ADMIN_PASSWORD = no Grafana login (observability.ps1 sets a random one nobody sees)."""
    password = values.get("GRAFANA_ADMIN_PASSWORD") or ""
    if password and len(password) < MIN_GRAFANA_PASSWORD:
        return [f"GRAFANA_ADMIN_PASSWORD: {MIN_GRAFANA_PASSWORD} or more characters, or no line (no login)"]
    return []


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("env_file", nargs="?", default=".env.uat", type=Path)
    parser.add_argument("--gate", action="store_true", help="check the settings instead of printing them")
    parser.add_argument(
        "--monitoring", action="store_true", help="with --gate: check the monitoring lines too"
    )
    parser.add_argument("--fingerprint", action="store_true", help="print a digest of the settings")
    args = parser.parse_args(argv)
    if not args.env_file.is_file():
        print(f"{args.env_file} not found", file=sys.stderr)
        return 1
    values = read_env(args.env_file)
    config, secret, left_out = split_settings(values)
    print(
        f"{args.env_file}: {len(config)} settings for the ConfigMap, {len(secret)} for the Secret; "
        f"left out: {', '.join(left_out) or 'none'}",
        file=sys.stderr,
    )
    if not args.gate:
        text = manifests(config, secret)
        print(hashlib.sha256(text.encode()).hexdigest()[:16] if args.fingerprint else text, end="")
        return 0
    problems = settings_problems(config | secret) + store_problems(config | secret)
    problems += gateway_problems(config | secret)
    problems += monitoring_problems(values) if args.monitoring else []
    for problem in problems:
        print(f"GATE FAILED  {problem}")
    if not problems:
        print(
            "GATE OK: the pods' settings load, every store is one the network rules allow, and every AI "
            "gateway is called directly."
        )
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
