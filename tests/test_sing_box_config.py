import json
import sys
from pathlib import Path
from uuid import UUID

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.utils.sing_box_config import SingBoxConfig
from v2share import V2Data


def render_config(configs, variant="dial"):
    singbox = SingBoxConfig(schema_variant=variant)
    singbox.add_proxies(configs)
    rendered = singbox.render()
    return json.loads(rendered)


def make_vmess(tag: str) -> V2Data:
    return V2Data(
        protocol="vmess",
        remark=tag,
        address="example.com",
        port=443,
        uuid=UUID("12345678-1234-5678-1234-567812345678"),
        tls="tls",
        sni="example.com",
    )


def test_render_injects_dial_for_chained_outbounds():
    first = make_vmess("node-a")
    second = make_vmess("node-b")
    first.next = second

    data = render_config([first], variant="dial")

    outbounds = {entry["tag"]: entry for entry in data["outbounds"]}

    assert "node-a" in outbounds
    assert outbounds["node-a"].get("dial", {}).get("detour") == "node-b"
    assert "detour" not in outbounds["node-a"]


def test_selector_and_urltest_outbounds_populated():
    first = make_vmess("node-a")
    data = render_config([first], variant="dial")

    selector = next(
        outbound
        for outbound in data["outbounds"]
        if outbound["type"] == "selector"
    )
    urltest = next(
        outbound
        for outbound in data["outbounds"]
        if outbound["type"] == "urltest"
    )

    assert "node-a" in selector["outbounds"]
    assert "node-a" in urltest["outbounds"]
    assert urltest["tolerance"] == 30


def test_dns_and_route_follow_new_schema_defaults():
    data = render_config([], variant="dial")

    dns = data["dns"]
    servers = {server["tag"]: server for server in dns["servers"]}

    assert dns["strategy"] == "prefer_ipv4"
    assert "dns-block" in servers
    assert servers["dns-remote"]["detour"] == "proxy"

    route = data["route"]
    dns_rule = route["rules"][0]
    local_rule = route["rules"][1]

    assert dns_rule["protocol"] == ["dns"]
    assert local_rule["outbound"] == "direct"
    assert "ip_cidr" in local_rule
    assert "geoip" not in local_rule
    assert "geoip" not in route
    assert route["geosite"]["download_detour"] == "direct"


def test_legacy_detour_mode_keeps_backward_compatibility():
    first = make_vmess("node-a")
    second = make_vmess("node-b")
    first.next = second

    data = render_config([first], variant="detour")

    outbounds = {entry["tag"]: entry for entry in data["outbounds"]}

    assert outbounds["node-a"].get("detour") == "node-b"
    assert "dial" not in outbounds["node-a"]

    dns = data["dns"]
    servers = {server["tag"]: server for server in dns["servers"]}
    assert dns["strategy"] == "prefer_ipv4"
    assert "dns-block" in servers
    assert "address_strategy" in servers["dns-remote"]

    route = data["route"]
    dns_rule = route["rules"][0]
    assert dns_rule["protocol"] == ["dns"]
    assert route["geosite"]["download_detour"] == "direct"
