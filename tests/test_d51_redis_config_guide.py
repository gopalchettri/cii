"""The deployment guide keeps up with the per-component Redis logins: Part 1 gives the Redis owner each
login's rights, step 7 fills in every login with its user name, and a next release's secrets check names a
Secret that is new in the template, so its pods do not stop for want of it."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.test_deploy import SECRETS_FILE, WATCHED, _objects, _redis_logins
from tests.test_deploy_monitoring_images import GUIDE

NO_POWERSHELL = pytest.mark.skipif(
    shutil.which("powershell") is None, reason="Windows PowerShell is not installed here"
)
ACL_LINE = re.compile(r"^ACL SETUSER (\S+) (.+)$", re.MULTILINE)
NEXT_RELEASE_SECRETS_STEP = "### Step 5. Apply the secrets and settings"


def _guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def _login_parts() -> set[str]:
    """The Redis logins the template asks for, by their placeholder: CHANGE_ME_<PART>_USER."""
    logins = [login for namespace in WATCHED for login in _redis_logins(namespace).values()]
    urls = [url for login in logins for url in login.values()]
    return {match.group(1) for url in urls if (match := re.search(r"CHANGE_ME_(\w+?)_USER", url))}


def test_the_guide_names_every_secret_of_the_template() -> None:
    """A Secret the guide never names is one an operator never fills in, and every pod that reads it stops
    with CreateContainerConfigError."""
    names = {o["metadata"]["name"] for o in _objects(SECRETS_FILE, kind="Secret")}
    assert {name for name in names if f"`{name}`" not in _guide()} == set()


def test_the_guide_never_writes_a_redis_url_without_a_user_name() -> None:
    """A Redis URL with no user name logs in as Redis' default user, never as the component's own login."""
    assert re.findall(r"rediss?://:\S*", _guide()) == []


def test_part_1_gives_the_redis_owner_one_acl_line_per_login() -> None:
    """One ACL line per login of the template, each on TSG's keys only. The app's logins get every channel:
    Celery subscribes to channel patterns, which Redis compares letter for letter with a user's channel rules,
    so `&tsg:*` alone refuses them and the workers stop (seen on a real Redis). redis-exporter only reads."""
    rules = {user: rule.split() for user, rule in ACL_LINE.findall(_guide())}
    parts = _login_parts()
    assert len(parts) == 5
    assert set(rules) == {f"tsg-{part.lower()}" for part in parts}
    assert all("~tsg:*" in rule and "reset" in rule for rule in rules.values())
    exporter = rules.pop("tsg-exporter")
    assert "-@all" in exporter and not {"+@all", "+@write", "allchannels"} & set(exporter)
    assert all({"allchannels", "+@all", "-@dangerous"} <= set(rule) for rule in rules.values())


def _run_secrets_check(folder: Path) -> list[str]:
    """Run Part 4's secrets check, as written in the guide, in `folder`; what it prints."""
    after = _guide()[_guide().index(NEXT_RELEASE_SECRETS_STEP) :]
    check = re.search(r"```powershell\n(.*?)```", after, re.DOTALL)
    assert check and "oc " not in check.group(1), "the step's first block must be the check alone"
    script = folder / "check.ps1"
    script.write_text(check.group(1), encoding="utf-8")
    powershell = [shutil.which("powershell") or "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass"]
    run = [*powershell, "-File", str(script)]
    result = subprocess.run(run, cwd=folder, capture_output=True, text=True, timeout=60, check=False)  # noqa: S603
    assert result.returncode == 0 and not result.stderr, result.stderr
    return result.stdout.split()


@NO_POWERSHELL
def test_a_next_release_s_secrets_check_names_each_new_secret(tmp_path: Path) -> None:
    """The release that brought the Redis logins: the operator's secrets.yaml from before it has the Redis
    URLs in tsg-secrets and none of the tsg-redis-* Secrets. The check names each Secret (and key) to copy
    over; once copied, it prints nothing."""
    (tmp_path / "deploy").mkdir()
    shutil.copy(SECRETS_FILE, tmp_path / "deploy" / SECRETS_FILE.name)
    template = yaml.safe_load(SECRETS_FILE.read_text(encoding="utf-8"))
    logins = [item for item in template["items"] if item["metadata"]["name"].startswith("tsg-redis-")]
    old = [item for item in template["items"] if item not in logins]
    for item in old:
        if item["metadata"]["name"] == "tsg-secrets":
            item["stringData"] = {**item["stringData"], **logins[0]["stringData"]}
    operator_copy = tmp_path / "deploy" / "secrets.yaml"
    operator_copy.write_text(yaml.safe_dump({**template, "items": old}), encoding="utf-8")
    new_keys = {key for item in logins for key in item["stringData"]} - set(logins[0]["stringData"])
    assert set(_run_secrets_check(tmp_path)) == {item["metadata"]["name"] for item in logins} | new_keys
    shutil.copy(SECRETS_FILE, operator_copy)
    assert _run_secrets_check(tmp_path) == []
