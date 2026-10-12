"""Installs the laptop monitoring tools (used by scripts/monitoring.py): the official Windows builds, at the
versions UAT pins, each checked against its release's SHA-256 before it is unpacked."""

from __future__ import annotations

import hashlib
import re
import shutil
import urllib.request
import zipfile
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[1]
TEMPLATE = REPO / "deploy" / "observability.yaml"
#: Not under AppData: Windows gives a packaged app (the Claude desktop app, a Store Python) its own private
#: AppData, and a stop from another window would not find what a start from this one installed.
ROOT = Path.home() / ".tsg" / "monitoring-v2"
GH = "https://github.com"

#: tool -> (archive URL, checksum-file URL, the program inside the archive). {v} = the pinned version.
DOWNLOADS = {
    "prometheus": (
        f"{GH}/prometheus/prometheus/releases/download/v{{v}}/prometheus-{{v}}.windows-amd64.zip",
        f"{GH}/prometheus/prometheus/releases/download/v{{v}}/sha256sums.txt",
        "prometheus.exe",
    ),
    "alertmanager": (
        f"{GH}/prometheus/alertmanager/releases/download/v{{v}}/alertmanager-{{v}}.windows-amd64.zip",
        f"{GH}/prometheus/alertmanager/releases/download/v{{v}}/sha256sums.txt",
        "alertmanager.exe",
    ),
    "loki": (
        f"{GH}/grafana/loki/releases/download/v{{v}}/loki-windows-amd64.exe.zip",
        f"{GH}/grafana/loki/releases/download/v{{v}}/SHA256SUMS",
        "loki-windows-amd64.exe",
    ),
    "alloy": (
        f"{GH}/grafana/alloy/releases/download/v{{v}}/alloy-windows-amd64.exe.zip",
        f"{GH}/grafana/alloy/releases/download/v{{v}}/SHA256SUMS",
        "alloy-windows-amd64.exe",
    ),
    "grafana": (
        "https://dl.grafana.com/oss/release/grafana-{v}.windows-amd64.zip",
        "https://dl.grafana.com/oss/release/grafana-{v}.windows-amd64.zip.sha256",
        "grafana.exe",
    ),
    "redis_exporter": (
        f"{GH}/oliver006/redis_exporter/releases/download/v{{v}}/redis_exporter-v{{v}}.windows-amd64.zip",
        f"{GH}/oliver006/redis_exporter/releases/download/v{{v}}/sha256sums.txt",
        "redis_exporter.exe",
    ),
}


def pinned_versions() -> dict[str, str]:
    """{tool: version} from the template's `image: ${REGISTRY}/<tool>:<tag>` lines (a leading v dropped)."""
    lines = re.findall(r"image: \$\{REGISTRY\}/([\w-]+):v?([\w.]+)", TEMPLATE.read_text(encoding="utf-8"))
    return dict(lines)


def install() -> None:
    """Download, verify and unpack each tool once (a tool already installed at its pinned version is kept)."""
    versions = pinned_versions()
    for tool, (url_template, sums_template, _) in DOWNLOADS.items():
        version = versions[tool]
        dest = ROOT / "bin" / f"{tool}-{version}"
        if (dest / ".installed").exists():
            continue
        url = url_template.format(v=version)
        archive = ROOT / "downloads" / url.rsplit("/", 1)[1]
        print(f"  downloading {tool} {version} from {urlparse(url).netloc}", flush=True)
        _download(url, archive)
        if _sha256(archive) != _expected_sha256(sums_template.format(v=version), archive.name):
            archive.unlink()
            raise SystemExit(f"checksum mismatch for {archive.name}: deleted, not used")
        shutil.rmtree(dest, ignore_errors=True)
        with zipfile.ZipFile(archive) as unpacked:
            unpacked.extractall(dest)  # zipfile refuses paths outside dest
        (dest / ".installed").write_text(url, encoding="utf-8")
        archive.unlink()


def program(tool: str) -> Path:
    """The installed program of a tool, e.g. ...\\prometheus-3.15.0\\...\\prometheus.exe."""
    folder = ROOT / "bin" / f"{tool}-{pinned_versions()[tool]}"
    return next(folder.rglob(DOWNLOADS[tool][2]))


def _download(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(url, timeout=60) as response, open(partial, "wb") as out:  # noqa: S310 — fixed https
        shutil.copyfileobj(response, out, 1 << 20)
    partial.replace(dest)


def _expected_sha256(sums_url: str, filename: str) -> str:
    with urllib.request.urlopen(sums_url, timeout=60) as response:  # noqa: S310 — fixed https URLs
        lines = response.read().decode("utf-8", "replace").splitlines()
    for line in lines:
        parts = line.split()
        if len(parts) == 1 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            return parts[0]  # a .sha256 file for this one archive
        if len(parts) >= 2 and parts[-1].lstrip("*").removeprefix("./") == filename:
            return parts[0].lower()
    raise SystemExit(f"no checksum for {filename} in {sums_url}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        while chunk := file.read(1 << 20):
            digest.update(chunk)
    return digest.hexdigest()
