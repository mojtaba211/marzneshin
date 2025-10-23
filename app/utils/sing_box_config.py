"""Sing-box configuration generator updated for Sing-box >= v1.13.

This module vendors a lightly modified copy of the upstream ``v2share``
``SingBoxConfig`` helper.  The upstream implementation still produces the
legacy structure that triggers deprecation warnings on recent Sing-box
releases.  The rewritten implementation here keeps the public API that the
rest of marzneshin relies on, while emitting the new ``dial``-based chained
outbound definitions and refreshed defaults for dns/route blocks.
"""

from __future__ import annotations

import json
import random
from importlib import resources
from typing import List

from v2share._utils import filter_dict
from v2share.base import BaseConfig
from v2share.data import V2Data
from v2share.exceptions import ProtocolNotSupportedError, TransportNotSupportedError


class SingBoxConfig(BaseConfig):
    """Render sing-box configurations with optional legacy compatibility."""

    chaining_support = True
    supported_protocols = [
        "shadowsocks",
        "vmess",
        "trojan",
        "vless",
        "hysteria2",
        "wireguard",
        "shadowtls",
        "tuic",
    ]
    supported_transports = [
        "tcp",
        "ws",
        "quic",
        "httpupgrade",
        "grpc",
        "http",
        "splithttp",
        None,
    ]

    def __init__(
        self,
        template_path: str | None = None,
        swallow_errors: bool = True,
        schema_variant: str = "dial",
    ):
        if not template_path:
            template_path = resources.files("app.templates") / "sing-box.json"
        with open(template_path) as file:
            self._template_data = file.read()
        self._swallow_errors = swallow_errors
        normalized_variant = schema_variant.lower()
        if normalized_variant not in {"dial", "detour"}:
            raise ValueError(
                "schema_variant must be either 'dial' (>=1.13) or 'detour' (<=1.12)"
            )
        self._schema_variant = normalized_variant
        self._configs: List[V2Data] = []

    def render(self, sort: bool = True, shuffle: bool = False):
        if shuffle:
            configs = random.sample(self._configs, len(self._configs))
        elif sort:
            configs = sorted(self._configs, key=lambda conf: conf.weight)
        else:
            configs = self._configs

        result = json.loads(self._template_data)

        chained_outbound_tags: set[str] = set()
        for config in configs:
            current = config
            while True:
                outbound = self.create_outbound(current)
                if current.next:
                    if self._schema_variant == "dial":
                        outbound.setdefault("dial", {})["detour"] = current.next.remark
                    else:
                        outbound["detour"] = current.next.remark
                    chained_outbound_tags.add(current.next.remark)
                    result["outbounds"].append(outbound)
                    current = current.next
                else:
                    result["outbounds"].append(outbound)
                    break

        urltest_types = {
            "hysteria2",
            "vmess",
            "vless",
            "trojan",
            "shadowsocks",
            "wireguard",
            "tuic",
            "shadowtls",
        }
        selector_types = urltest_types | {"urltest"}

        outbounds = result.get("outbounds", [])
        urltest_tags = [
            outbound["tag"]
            for outbound in outbounds
            if outbound.get("type") in urltest_types
            and outbound.get("tag") not in chained_outbound_tags
        ]
        selector_tags = [
            outbound["tag"]
            for outbound in outbounds
            if outbound.get("type") in selector_types
            and outbound.get("tag") not in chained_outbound_tags
        ]

        for outbound in outbounds:
            if outbound.get("type") == "urltest" and not outbound.get("outbounds"):
                outbound["outbounds"] = urltest_tags

        for outbound in outbounds:
            if outbound.get("type") == "selector" and not outbound.get("outbounds"):
                outbound["outbounds"] = selector_tags

        return json.dumps(result, indent=4)

    @staticmethod
    def tls_config(
        sni=None,
        fp=None,
        tls=None,
        pbk=None,
        sid=None,
        alpn=None,
        ais=None,
    ):
        config = {}
        if tls in ["tls", "reality"]:
            config["enabled"] = True

        if sni is not None:
            config["server_name"] = sni

        if tls == "tls" and ais:
            config["insecure"] = ais

        if tls == "reality":
            config["reality"] = {"enabled": True}
            if pbk:
                config["reality"]["public_key"] = pbk
            if sid:
                config["reality"]["short_id"] = sid
            if alpn:
                config["reality"]["alpn"] = alpn

        if alpn and tls == "tls":
            config["alpn"] = alpn

        if fp:
            config["utls"] = {"enabled": True, "fingerprint": fp}

        return config

    @staticmethod
    def transport_config(
        transport_type="tcp",
        host=None,
        path=None,
        headers=None,
        early_data=None,
    ):
        headers = headers or {}
        transport_config = {"type": transport_type}

        if transport_type in {"http", "tcp", "splithttp"}:
            transport_config["type"] = "http" if transport_type != "splithttp" else "splithttp"
            if headers:
                transport_config["headers"] = headers
            if host:
                hosts_value = [host] if transport_type != "splithttp" else host
                transport_config["host"] = hosts_value
            if path:
                transport_config["path"] = path
        elif transport_type == "ws":
            if headers:
                transport_config["headers"] = headers
            if host:
                transport_config.setdefault("headers", {})["Host"] = host
            if path:
                transport_config["path"] = path
            if early_data:
                transport_config["early_data_header_name"] = "Sec-WebSocket-Protocol"
                transport_config["max_early_data"] = early_data
        elif transport_type == "httpupgrade":
            if headers:
                transport_config["headers"] = headers
            if host:
                transport_config["host"] = host
            if path:
                transport_config["path"] = path
        elif transport_type == "grpc":
            if path:
                transport_config["service_name"] = path

        return transport_config

    @staticmethod
    def create_outbound(config: V2Data):
        outbound = {
            "type": config.protocol,
            "tag": config.remark,
            "server": config.address,
            "server_port": config.port,
        }

        if (
            config.protocol == "vless"
            and config.flow
            and config.tls in ["tls", "reality"]
        ):
            outbound["flow"] = config.flow

        if config.transport_type in [
            "ws",
            "quic",
            "grpc",
            "httpupgrade",
            "http",
            "splithttp",
        ] or (config.transport_type == "tcp" and config.header_type == "http"):
            outbound["transport"] = SingBoxConfig.transport_config(
                transport_type=config.transport_type,
                host=config.host,
                path=config.path,
                headers=config.http_headers,
                early_data=config.early_data,
            )

        if config.tls in ("tls", "reality"):
            outbound["tls"] = SingBoxConfig.tls_config(
                sni=config.sni,
                fp=config.fingerprint,
                tls=config.tls,
                pbk=config.reality_pbk,
                sid=config.reality_sid,
                alpn=config.alpn,
                ais=config.allow_insecure,
            )

        if config.protocol in ["vless", "vmess"]:
            outbound["uuid"] = str(config.uuid)

        elif config.protocol == "trojan":
            outbound["password"] = config.password

        elif config.protocol == "shadowsocks":
            outbound["password"] = config.password
            outbound["method"] = config.shadowsocks_method
        elif config.protocol == "hysteria2":
            outbound["password"] = config.password
            if config.header_type:
                outbound["obfs"] = {
                    "type": config.header_type,
                    "password": config.path,
                }
        elif config.protocol == "wireguard":
            outbound.update(
                {
                    "private_key": config.ed25519,
                    "local_address": [config.client_address],
                    "mtu": config.mtu,
                    "peers": [
                        {
                            "server": config.address,
                            "server_port": config.port,
                            "public_key": config.path,
                            "allowed_ips": config.allowed_ips
                            or ["0.0.0.0/0", "::/0"],
                        }
                    ],
                }
            )
        elif config.protocol == "shadowtls":
            if config.shadowtls_version:
                outbound["version"] = config.shadowtls_version
                if config.shadowtls_version in {2, 3}:
                    outbound["password"] = config.password
        elif config.protocol == "tuic":
            outbound["password"] = config.password
            outbound["uuid"] = str(config.uuid)

        if config.mux_settings is not None and config.mux_settings.protocol in {
            "h2mux",
            "yamux",
            "smux",
        }:
            outbound["multiplex"] = {
                "enabled": True,
                "protocol": config.mux_settings.protocol,
            }
            if config.mux_settings.sing_box_mux_settings is not None:
                additional_mux_settings = filter_dict(
                    {
                        "max_connections": config.mux_settings.sing_box_mux_settings.max_connections,
                        "min_streams": config.mux_settings.sing_box_mux_settings.min_streams,
                        "max_streams": config.mux_settings.sing_box_mux_settings.max_streams,
                        "padding": config.mux_settings.sing_box_mux_settings.padding,
                    },
                    (None,),
                )
                outbound["multiplex"].update(additional_mux_settings)
        return outbound

    def add_proxies(self, proxies: List[V2Data]):
        for proxy in proxies:
            unsupported_transport = proxy.transport_type not in self.supported_transports
            unsupported_protocol = proxy.protocol not in self.supported_protocols

            if unsupported_transport or unsupported_protocol:
                if self._swallow_errors:
                    continue
                if unsupported_transport:
                    raise TransportNotSupportedError
                if unsupported_protocol:
                    raise ProtocolNotSupportedError

            self._configs.append(proxy)

