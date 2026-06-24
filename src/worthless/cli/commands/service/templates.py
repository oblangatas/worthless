"""Platform unit/plist templates for ``worthless service install``."""

from __future__ import annotations

LAUNCHD_LABEL = "dev.worthless.proxy"
SYSTEMD_UNIT_NAME = "worthless-proxy.service"


def launchd_plist_path(home: str) -> str:
    return f"{home}/Library/LaunchAgents/{LAUNCHD_LABEL}.plist"


def systemd_unit_path(home: str) -> str:
    return f"{home}/.config/systemd/user/{SYSTEMD_UNIT_NAME}"


def render_launchd_plist(
    *,
    binary: str,
    worthless_home: str,
    log_path: str,
    port: int | None = None,
) -> str:
    """Return a LaunchAgent plist string for foreground ``worthless up``."""
    env_entries = [
        "    <key>WORTHLESS_SERVICE_MANAGED</key>",
        "    <string>1</string>",
        "    <key>WORTHLESS_HOME</key>",
        f"    <string>{worthless_home}</string>",
    ]
    if port is not None:
        env_entries.extend(
            [
                "    <key>WORTHLESS_PORT</key>",
                f"    <string>{port}</string>",
            ]
        )
    env_block = "\n".join(env_entries)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{binary}</string>
    <string>up</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
{env_block}
  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ThrottleInterval</key>
  <integer>5</integer>
  <key>StandardOutPath</key>
  <string>{log_path}</string>
  <key>StandardErrorPath</key>
  <string>{log_path}</string>
</dict>
</plist>
"""


def render_systemd_unit(
    *,
    binary: str,
    worthless_home: str,
    port: int | None = None,
) -> str:
    """Return a systemd user unit for foreground ``worthless up``."""
    env_lines = [
        "Environment=WORTHLESS_SERVICE_MANAGED=1",
        f"Environment=WORTHLESS_HOME={worthless_home}",
    ]
    if port is not None:
        env_lines.append(f"Environment=WORTHLESS_PORT={port}")
    env_block = "\n".join(env_lines)
    return f"""[Unit]
Description=Worthless local proxy
After=network.target

[Service]
Type=simple
ExecStart={binary} up
Restart=on-failure
RestartSec=5s
{env_block}
NoNewPrivileges=true
LimitCORE=0
UMask=0077
UnsetEnvironment=WORTHLESS_FERNET_KEY

[Install]
WantedBy=default.target
"""
