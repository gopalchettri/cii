"""The monitoring proxy and Grafana move few bytes and fail fast: nginx never spills a request or an answer
to disk and gives up on a blocked connection in seconds, its config is checked in its own image before UAT,
it reserves what the quota counts anyway, and Grafana compresses its answers and serves no metrics page.
Grafana's missing login is written down where the public addresses are."""

import re

from tests.test_deploy import COMMON_FILE, PROXY, REPO, _container, _deployment
from tests.test_deploy_monitoring_images import BUILD_SCRIPT, GUIDE
from tests.test_deploy_monitoring_proxy import NGINX_CONF

#: build-monitoring-images.bat's nginx -t: (user, --add-host flags, mounted folder, mount path, nginx args).
NGINX_TEST = re.compile(
    r"docker run --rm --user (\S+) ((?:--add-host \S+ )+)"
    r'-v "%CD%\\([^:]+):([^:]+):ro" "%IMAGE%" -t ([^>]+?) >'
)


def _http_settings() -> dict[str, str]:
    """nginx.conf's settings at the http level (before its server block)."""
    conf = NGINX_CONF.read_text(encoding="utf-8")
    http = conf[conf.index("http {") : conf.index("server {")]
    return dict(re.findall(r"^    (\w+) ([^;]+);", http, re.MULTILINE))


def test_the_proxy_keeps_bodies_in_memory_and_gives_up_on_a_blocked_connection_in_seconds() -> None:
    """nginx keeps bodies up to 64k in memory, writes no answer to disk, and stops connecting after 5 s."""
    settings = _http_settings()
    assert settings["client_body_buffer_size"] == "64k"
    assert settings["proxy_max_temp_file_size"] == "0"
    timeout = settings["proxy_connect_timeout"]
    assert timeout == "5s"
    guide = GUIDE.read_text(encoding="utf-8")
    [seconds] = re.findall(r"`504 Gateway Time-out` \(after about (\d+) seconds\)", guide)
    assert f"{seconds}s" == timeout


def test_the_build_script_checks_the_config_the_proxy_pod_loads_in_its_image() -> None:
    """nginx -t runs with the pod's arguments, mount path and user, and Grafana's and Flower's names set."""
    [(user, hosts, source, mount, args)] = NGINX_TEST.findall(BUILD_SCRIPT.read_text(encoding="utf-8"))
    container = _container(_deployment(PROXY))
    assert args.split() == container["args"]
    [config] = [m["mountPath"] for m in container["volumeMounts"] if m["name"] == "config"]
    assert mount == config
    assert REPO / source.replace("\\", "/") / NGINX_CONF.name == NGINX_CONF
    assert f"{mount}/{NGINX_CONF.name}" in container["args"]
    assert user == "1000870000:0"
    upstreams = set(re.findall(r"proxy_pass http://([\w.-]+):\d+;", NGINX_CONF.read_text(encoding="utf-8")))
    assert {host.partition(":")[0] for host in re.findall(r"--add-host (\S+)", hosts)} == upstreams


def test_every_build_of_the_images_by_name_also_checks_the_proxy_config() -> None:
    """After building the images by name, the guide runs nginx -t unpushed: nginx may be in Quay already."""
    blocks = re.findall(r"```powershell\n(.*?)```", GUIDE.read_text(encoding="utf-8"), re.DOTALL)
    by_name = "foreach ($n in $names) { deploy\\build-monitoring-images.bat $n }"
    loops = [block for block in blocks if by_name in block]
    check = "\ndeploy\\build-monitoring-images.bat nginx --no-push\n"
    assert len(loops) == 2 and all(block.endswith(check) for block in loops)
    script = BUILD_SCRIPT.read_text(encoding="utf-8")
    skips_quay = script.index('if "%PUSH%"=="0" goto image_build')
    assert skips_quay < script.index("docker manifest inspect") < script.index('"%IMAGE%" -t ')


def test_the_proxy_reserves_what_the_quota_counts_anyway() -> None:
    """The proxy's requests equal its limits, which ai-threatgen's quota counts."""
    resources = _container(_deployment(PROXY))["resources"]
    assert resources["requests"] == resources["limits"]


def test_grafana_compresses_its_answers_and_serves_no_metrics_page() -> None:
    """Grafana gzips its answers and turns off its own /metrics page, which nothing scrapes."""
    grafana = _deployment("grafana")
    env = {e["name"]: e.get("value") for e in _container(grafana)["env"]}
    assert (env["GF_SERVER_ENABLE_GZIP"], env["GF_METRICS_ENABLED"]) == ("true", "false")
    assert "prometheus.io/scrape" not in grafana["spec"]["template"]["metadata"].get("annotations", {})


def test_grafana_s_missing_login_is_written_where_its_address_is() -> None:
    """Guide Part 3 and the deploy_common.yaml header say no login opens every log line and metric."""
    guide = GUIDE.read_text(encoding="utf-8")
    part_3 = guide[guide.index("## Part 3.") : guide.index("### Step 1.", guide.index("## Part 3."))]
    header = COMMON_FILE.read_text(encoding="utf-8").split("\n\n")[0]
    for text in (part_3, header):
        assert "every log line and metric" in " ".join(text.split())
