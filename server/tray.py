"""SystemTrayIconManager, the system tray icon and its menu (only used by
the Windows build)."""

import os
import platform
import re
import subprocess
import threading as th

try:
    from PIL import Image
    sc4mp_has_pil = True
except ImportError:
    sc4mp_has_pil = False

try:
    import pystray
    sc4mp_has_pystray = True
except ImportError:
    sc4mp_has_pystray = False

from core.util import get_public_ip_address, set_thread_name
from server import state
from server.constants import SC4MP_ICON, SC4MP_INVITES_DOMAIN, SC4MP_LOG_PATH
from server.errors import fatal_error, show_error


class SystemTrayIconManager(th.Thread):
    """The system tray icon and its menu. The icon runs its own loop, so it
    gets its own thread."""

    def __init__(self):

        super().__init__()

        if state.sc4mp_server_path == "_SC4MP":
            self.helper_batch_directory = os.getcwd()
        else:
            self.helper_batch_directory = state.sc4mp_server_path

        Menu = pystray.Menu
        Item = pystray.MenuItem
        Icon = pystray.Icon

        # details = []
        # for section in sc4mp_config.data.keys():
        #     details += [Item(section, None, enabled=False)]
        #     for key, value in sc4mp_config.data[section].items():
        #         details += [Item(f"{key}: {value}", None, enabled=False)]
        #     details += [Item("", None, enabled=False)]
        # details.pop(-1)

        self.server_name = state.sc4mp_config['INFO']['server_name']

        address = "localhost"
        if state.sc4mp_config['NETWORK']['host'] != "127.0.0.1":
            public_address = get_public_ip_address(timeout=5)
            if public_address:
                address = public_address

        if address == "localhost":
            connect = Item("Connect", lambda: self.connect("localhost"))
        else:
            connect = Item("Connect...", Menu(
                Item("Via LAN", lambda: self.connect("localhost")),
                Item("Via internet", lambda: self.connect(address)),
            ))

        name = "system_tray_icon"
        icon = Image.open(SC4MP_ICON)
        title = self.server_name
        menu = Menu(
            # Item("Details...", Menu(*details)),
            Item("Actions...", Menu(
                connect,
                # Item(
                #     "Trigger FATAL ERROR", lambda: fatal_error(Exception())
                # ),
                # Item("Update", self.update),
                Item("Restart", self.restart),
                Item("Stop", self.stop),
            )),
            Item("Manage...", Menu(
                Item("Plugins", self.plugins),
                Item("Regions", self.regions),
            )),
            Item("Edit...", Menu(
                Item("Config", self.config),
                # Item("Router settings", self.router),
                # Item("Firewall settings", self.firewall),
            )),
            Item("View...", Menu(
                Item("Logs", self.logs),
                # Item("Invite", self.invite),
                Item("Readme", self.readme),
            )),
            # Item("Help...", Menu(
            #     Item("Readme", self.readme),
            # )),
        )

        self.icon = Icon(name, icon, title, menu)

    def status(self, status="", notification=""):

        title = self.icon.title

        if notification and self.icon.HAS_NOTIFICATION:
            self.icon.title = self.server_name
            self.icon.notify(notification)
        if status:
            self.icon.title = f"{self.server_name} ({status})"
        else:
            self.icon.title = title

    def error(self, e, notification=""):

        show_error(e)

        if not notification:
            notification = (
                "An error occurred. Please check the logs at "
                "\"Documents\\SimCity 4\\SC4MP Server\\sc4mpserver.log\" "
                "for more details."
            )

        self.status(notification=notification)

    def run(self):

        try:

            set_thread_name("TrayThread")

            self.icon.run()

        except Exception as e:

            fatal_error(e)

    def restart(self, icon, item):

        try:

            start_bat = os.path.join(self.helper_batch_directory, "start.bat")
            subprocess.Popen([start_bat])

        except Exception as e:

            self.error(e)

    def stop(self, icon, item):

        try:

            stop_bat = os.path.join(self.helper_batch_directory, "stop.bat")
            subprocess.Popen([stop_bat])

        except Exception as e:

            fatal_error(e)

    def connect(self, address="localhost"):

        try:

            # The launcher handles sc4mp:// links
            port = state.sc4mp_config['NETWORK']['port']
            os.startfile(f"sc4mp://{address}:{port}")

        except Exception as e:

            self.error(
                e,
                notification=(
                    "Unable to connect. Ensure the SC4MP Launcher is "
                    "installed, then try again."
                )
            )

    def logs(self, icon, item):

        try:

            logs_bat = os.path.join(self.helper_batch_directory, "logs.bat")

            # logs.bat uses PowerShell, which needs Windows 10 or later
            windows_version = int(platform.version().split('.')[0])
            if windows_version >= 10 and os.path.exists(logs_bat):
                os.startfile(logs_bat)
            else:
                os.startfile(SC4MP_LOG_PATH)

        except Exception as e:

            self.error(e)

    def plugins(self, icon, item):

        try:

            self.status(
                notification="Add plugins by pasting the plugin files here."
            )

            os.startfile(os.path.join(state.sc4mp_server_path, "Plugins"))

        except Exception as e:

            self.error(e)

    def regions(self, icon, item):

        try:

            self.status(
                notification=(
                    "Add regions by pasting the region folders here. When "
                    "you're done, restart the server for the changes to take "
                    "effect."
                )
            )

            os.startfile(os.path.join(state.sc4mp_server_path, "Regions"))

        except Exception as e:

            self.error(e)

    def config(self, icon, item):

        try:

            self.status(
                notification=(
                    "Edit the server configuration settings here, then "
                    "restart the server for the changes to take effect."
                )
            )

            config_path = os.path.join(
                state.sc4mp_server_path, "serverconfig.ini"
            )
            os.startfile(config_path)

        except Exception as e:

            self.error(e)

    def invite(self, icon, item):

        try:

            server_id = state.sc4mp_config['INFO']['server_id']
            os.startfile(f"https://{SC4MP_INVITES_DOMAIN}/{server_id}")

        except Exception as e:

            self.error(e)

    def readme(self, icon, item):

        try:

            os.startfile("Readme.html")

        except Exception as e:

            self.error(e)

    def update(self, icon, item):

        try:

            subprocess.Popen(["update.bat"])

        except Exception as e:

            self.error(e)

    def router(self):

        try:

            # Run 'ipconfig' and capture the output
            output = subprocess.run(
                "ipconfig", capture_output=True, text=True, check=True
            )

            # Search for 'Default Gateway' in the output
            match = re.search(r"Default Gateway[ .:]+([\d.]+)", output.stdout)

            if match:
                router_ip = match.group(1)
                os.startfile(f"http://{router_ip}")

        except Exception as e:

            self.error(e)

    def firewall(self):

        try:

            os.startfile("C:\\Windows\\system32\\WF.msc")

        except Exception as e:

            self.error(e)
