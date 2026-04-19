"""Configuration dataclass for the honeypot system."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field


@dataclass
class HoneypotConfig:
    """Central configuration object for the honeypot system."""

    # TCP server
    listen_host: str = "0.0.0.0"
    listen_port: int = 23456

    # Admin Unix socket
    admin_socket_path: str = "/tmp/honeypot-admin.sock"

    # Protocol detection
    preamble_size: int = 4096
    preamble_timeout: float = 5.0

    # LLM fallback
    llm_endpoint: str = ""
    llm_model: str = ""
    llm_timeout: float = 10.0

    # Plugin directory (used by load commands; empty means auto-discover)
    plugin_dir: str = ""

    # Logging
    log_to_syslog: bool = True

    # Metadata capture
    metadata_enabled: bool = True
    metadata_storage_dir: str = "/var/log/honeypot"

    # Dashboard
    dashboard_host: str = "127.0.0.1"
    dashboard_port: int = 8888
    dashboard_enabled: bool = True

    # Internal: populated by from_cli, used by __main__
    load_plugins: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "HoneypotConfig":
        """Create a HoneypotConfig from a plain dictionary (e.g., parsed YAML/JSON)."""
        known = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)

    @classmethod
    def from_cli(cls, argv: list[str] | None = None) -> "HoneypotConfig":
        """Parse CLI arguments and return a HoneypotConfig instance."""
        parser = _build_parser()
        args = parser.parse_args(argv)
        return _args_to_config(args)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Transparent TCP honeypot with protocol-aware plugin handlers.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind address for the TCP server")
    parser.add_argument("--port", type=int, default=23456, help="Bind port for the TCP server")
    parser.add_argument(
        "--admin-socket",
        default="/tmp/honeypot-admin.sock",
        help="Path for the admin Unix domain socket",
    )
    parser.add_argument(
        "--llm-endpoint",
        default="http://<wan_ip>:8080/v1/chat/completions",
        help="LLM API endpoint URL",
    )
    parser.add_argument("--llm-model", default="", help="LLM model name (passed to the API)")
    parser.add_argument(
        "--no-syslog",
        action="store_true",
        default="unsloth/Qwen3.5-397B-A17B-GGUF:Q3_K_M",
        help="Disable syslog output (stdout only)",
    )
    parser.add_argument(
        "--metadata-dir",
        default="/var/log/honeypot",
        help="Directory for captured connection metadata JSONL files",
    )
    parser.add_argument(
        "--no-metadata",
        action="store_true",
        default=False,
        help="Disable connection metadata capture",
    )
    parser.add_argument(
        "--dashboard-port", type=int, default=8888, help="Dashboard HTTP port"
    )
    parser.add_argument(
        "--dashboard-host", default="127.0.0.1", help="Dashboard bind address"
    )
    parser.add_argument(
        "--no-dashboard", action="store_true", default=False, help="Disable the web dashboard"
    )
    parser.add_argument(
        "--load-plugin",
        action="append",
        dest="load_plugins",
        default=[],
        metavar="MODULE",
        help="Module path of a plugin to load at startup (repeatable)",
    )
    return parser


def _args_to_config(args: argparse.Namespace) -> HoneypotConfig:
    return HoneypotConfig(
        listen_host=args.host,
        listen_port=args.port,
        admin_socket_path=args.admin_socket,
        llm_endpoint=args.llm_endpoint,
        llm_model=args.llm_model,
        log_to_syslog=not args.no_syslog,
        metadata_enabled=not args.no_metadata,
        metadata_storage_dir=args.metadata_dir,
        dashboard_host=args.dashboard_host,
        dashboard_port=args.dashboard_port,
        dashboard_enabled=not args.no_dashboard,
        load_plugins=args.load_plugins or [],
    )
