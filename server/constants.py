"""Values that never change while the server runs: version, URLs, file
paths, timings and the default config."""

import os

from core.util import (
    format_title,
    generate_server_id,
    generate_server_name,
    get_server_list,
    is_frozen,
    is_windows,
)


SC4MP_VERSION = "0.9.0"

SC4MP_SERVERS = get_server_list()

SC4MP_GITHUB_REPO = "kegsmr/sc4mp-server"

SC4MP_URL = "www.sc4mp.org"
SC4MP_CONTRIBUTORS_URL = (
    f"https://github.com/{SC4MP_GITHUB_REPO}/contributors/"
)
SC4MP_ISSUES_URL = f"https://github.com/{SC4MP_GITHUB_REPO}/issues/"
SC4MP_RELEASES_URL = f"https://github.com/{SC4MP_GITHUB_REPO}/releases/"

SC4MP_AUTHOR_NAME = "SimCity 4 Multiplayer Project"
SC4MP_WEBSITE_NAME = "www.sc4mp.org"
SC4MP_LICENSE_NAME = "MIT-0"

SC4MP_LOG_PATH = "sc4mpserver.log"
SC4MP_README_PATH = "readme.html"
SC4MP_RESOURCES_PATH = "resources"

SC4MP_TITLE = format_title("SC4MP Server", version=SC4MP_VERSION)
SC4MP_ICON = os.path.join(SC4MP_RESOURCES_PATH, "icon.ico")

SC4MP_BUFFER_SIZE = 4096

SC4MP_DELAY = .1

SC4MP_CONFIG_DEFAULTS = [
    ("NETWORK", [
        ("host", "0.0.0.0"),
        ("port", 7240),
        # ("upnp", False),  # TODO
        # TODO for servers hosted on a DDNS or other specific domain
        # ("domain", None),
        ("discoverable", True),
        ("domain", '')
    ]),
    ("INFO", [
        ("server_id", generate_server_id()),
        ("server_name", generate_server_name()),
        ("server_description", (
            "Join and build your city.\n\n"
            "Rules:\n"
            "- Feed the llamas\n"
            "- Balance your budget\n"
            "- Do uncle Vinny some favors"
        )),
        ("server_url", SC4MP_URL),
    ]),
    ("SECURITY", [
        ("private", False),
        ("password_enabled", False),
        ("password", "maxis2003"),
        ("max_ip_users", 3),
    ]),
    ("RULES", [
        ("claim_duration", 30),
        # TODO for resetting old abandoned saves
        # ("abandoned_reset_delay", None)
        # TODO prevent users from making another claim within this time
        # ("claim_timeout", None),
        ("max_region_claims", 1),
        # TODO max claims accross entire server
        # ("max_total_claims", None),
        ("godmode_filter", True),
        ("user_plugins", False),
    ]),
    ("PERFORMANCE", [
        ("request_limit", 60),
        ("max_request_threads", 200),
        ("connection_timeout", 600),
        ("filetable_update_interval", 600),
    ]),
    ("BACKUPS", [
        ("server_backup_interval", 6),
        ("backup_server_on_startup", True),
        ("max_server_backup_days", 30),
        ("max_savegame_backups", 20),
    ])
]

# The system tray icon only exists in the Windows build
if is_windows() and is_frozen():
    SC4MP_CONFIG_DEFAULTS += [
        ("UI", [
            ("enabled", True)
        ])
    ]

SC4MP_INVITES_DOMAIN = "invite.sc4mp.org"
