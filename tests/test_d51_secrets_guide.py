"""The deployment guide keeps up with the secrets template: it names every Secret an operator fills in, and a
next release's secrets check names each Secret or key that is new in the template, so no pod stops for want
of it."""

import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from tests.test_deploy import SECRETS_FILE, _objects
from tests.test_deploy_monitoring_images import GUIDE

NO_POWERSHELL = pytest.mark.skipif(
    shutil.which("powershell") is None, reason="Windows PowerShell is not installed here"
)
NEXT_RELEASE_SECRETS_STEP = "### Step 5. Apply the secrets and settings"
ALERT_EMAIL_KEYS = {"SMTP_RELAY_PASSWORD", "GMAIL_APP_PASSWORD"}


def _guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def test_the_guide_names_every_secret_of_the_template() -> None:
    """A Secret the guide never names is one an operator never fills in, and every pod that reads it stops
    with CreateContainerConfigError."""
    names = {o["metadata"]["name"] for o in _objects(SECRETS_FILE, kind="Secret")}
    assert {name for name in names if f"`{name}`" not in _guide()} == set()


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


def _operator_copy(folder: Path, items: list[dict]) -> Path:
    """An operator's secrets.yaml holding `items`, beside the release's template, in `folder`/deploy."""
    (folder / "deploy").mkdir(exist_ok=True)
    shutil.copy(SECRETS_FILE, folder / "deploy" / SECRETS_FILE.name)
    template = yaml.safe_load(SECRETS_FILE.read_text(encoding="utf-8"))
    copy = folder / "deploy" / "secrets.yaml"
    copy.write_text(yaml.safe_dump({**template, "items": items}), encoding="utf-8")
    return copy


@NO_POWERSHELL
def test_a_next_release_s_secrets_check_names_each_new_key_and_secret(tmp_path: Path) -> None:
    """The release that brought alert email: the operator's tsg-monitoring has no email passwords yet, so the
    check names both keys. A missing Secret is named with its keys. Once copied over, it prints nothing."""
    items = yaml.safe_load(SECRETS_FILE.read_text(encoding="utf-8"))["items"]
    [monitoring] = [item for item in items if item["metadata"]["name"] == "tsg-monitoring"]
    others = [item for item in items if item is not monitoring]
    kept = {key: value for key, value in monitoring["stringData"].items() if key not in ALERT_EMAIL_KEYS}
    _operator_copy(tmp_path, [*others, {**monitoring, "stringData": kept}])
    assert set(_run_secrets_check(tmp_path)) == ALERT_EMAIL_KEYS
    _operator_copy(tmp_path, others)
    assert set(_run_secrets_check(tmp_path)) == {"tsg-monitoring", *monitoring["stringData"]}
    shutil.copy(SECRETS_FILE, tmp_path / "deploy" / "secrets.yaml")
    assert _run_secrets_check(tmp_path) == []
