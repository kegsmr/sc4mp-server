"""Server, the main thread: it prepares everything, then accepts
connections and starts a RequestHandler for each one."""

import os
import socket
import threading as th
import time
from datetime import datetime, timedelta

from core.networking import ServerSocket
from server import state
from server.constants import SC4MP_DELAY
from server.errors import fatal_error, show_error
from server.request_handler import RequestHandler
from server.startup import StartupMixin
from server.updater import UpdaterMixin
from server.utils import report, set_headers


class Server(StartupMixin, UpdaterMixin, th.Thread):
    """The main server thread. Creating it runs all the startup steps
    (see StartupMixin); `run()` then accepts connections until the server
    stops."""

    def __init__(self):

        super().__init__()

        self.BIND_RETRY_DELAY = 5

        self.load_config()
        self.create_subdirectories()
        self.check_updates()
        self.prep_database()
        self.clear_temp()
        self.prep_filetables()
        self.prep_regions()
        self.prep_backups()
        self.prep_server_list()
        # self.prep_upnp()

    def run(self):

        try:

            report("Starting server...")

            report("- creating socket...")
            s = self.socket()

            # Allow binding the port again right after a restart, while
            # connections from before are in TIME_WAIT (not on Windows, where
            # this would let other programs bind the same port)
            if os.name != "nt":
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            report(
                "- binding host " + state.SC4MP_HOST + " and port "
                + str(state.SC4MP_PORT) + "..."
            )
            while True:
                try:
                    s.bind((state.SC4MP_HOST, state.SC4MP_PORT))
                    break
                except OSError as e:
                    show_error(e)
                    print(
                        f"[WARNING] - failed to bind socket, retrying in "
                        f"{self.BIND_RETRY_DELAY} seconds..."
                    )
                    time.sleep(self.BIND_RETRY_DELAY)

            if state.sc4mp_system_tray_icon_manager:
                state.sc4mp_system_tray_icon_manager.status(
                    "Running",
                    f"Listening on port {state.SC4MP_PORT}. You may now use "
                    f"the SC4MP Launcher to join."
                )

            report("- listening for connections...")
            s.listen(5)

            state.sc4mp_server_running = True

            performance = state.sc4mp_config["PERFORMANCE"]
            max_request_threads = performance["max_request_threads"]

            # Number of connections from each host in the last minute, to
            # enforce the request limit
            client_requests = {}
            client_requests_cleared = datetime.now()

            while state.sc4mp_server_running:

                next_clear = client_requests_cleared + timedelta(seconds=60)
                if datetime.now() >= next_clear:

                    client_requests = {}
                    client_requests_cleared = datetime.now()

                if (max_request_threads is None
                        or state.sc4mp_request_threads < max_request_threads):

                    try:

                        c, (host, port) = s.accept()

                        c.settimeout(performance["connection_timeout"])

                        request_limit = performance["request_limit"]
                        over_limit = (
                            request_limit is not None
                            and host in client_requests
                            and client_requests[host] >= request_limit
                        )
                        if over_limit:
                            print(
                                "[WARNING] Connection blocked from "
                                + str(host) + ":" + str(port) + "."
                            )
                            c.close()
                            continue
                        else:
                            client_requests.setdefault(host, 0)
                            client_requests[host] += 1

                        report(
                            "Connection accepted with " + str(host) + ":"
                            + str(port) + "."
                        )

                        self.log_client(c)

                        state.sc4mp_request_threads += 1

                        RequestHandler(c).start()

                    except Exception as e:  # socket.error as e:

                        show_error(e)

                else:

                    print("[WARNING] Request thread limit reached!")

                    # Wait until a request handler thread finishes
                    while not (
                        state.sc4mp_request_threads < max_request_threads
                    ):
                        time.sleep(SC4MP_DELAY)

        except (SystemExit, KeyboardInterrupt):

            pass

        except Exception as e:

            fatal_error(e)

        finally:

            report("Shutting down...")
            state.sc4mp_server_running = False

    def socket(self) -> ServerSocket:

        s = ServerSocket()
        set_headers(s)
        return s

    def log_client(self, c):

        # Get ip
        ip = c.getpeername()[0]

        # Get clients database
        clients_data = state.sc4mp_clients_database_manager

        # Get data entry that matches ip
        client_entry = None
        try:
            client_entry = clients_data[ip]
        except Exception:
            client_entry = {}
            clients_data[ip] = client_entry

        # Set values
        client_entry.setdefault("users", [])
        client_entry.setdefault("ban", False)
        first_contact = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_entry.setdefault("first_contact", first_contact)
        last_contact = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        client_entry["last_contact"] = last_contact
