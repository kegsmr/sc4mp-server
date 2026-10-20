"""ServerList, which finds other servers and shares the list of servers
with them."""

from __future__ import annotations

import os
import random
import threading as th
import time
from collections import deque
from typing import Iterable

from core.networking import ClientSocket, NetworkException
from core.util import set_thread_name
from server import state
from server.constants import SC4MP_DELAY, SC4MP_SERVERS
from server.errors import ServerException, show_error
from server.utils import load_json, set_headers, update_json


class ServerList(th.Thread):
    """Every minute or so, contacts one known server: asks it to add this
    server to its list and adds the servers it knows to the queue. The
    servers found are saved in `_Database/servers.json`."""

    class ServerQueue:
        """
        Queue for server scanning that implements membership check before
        enqueuing. Can optionally enqueue to the front (left) of the queue.
        The queue contains (host, port) tuples.
        """

        def __init__(self, servers: Iterable[tuple[str, int]]) -> None:
            self._queue = deque(servers)

        def __len__(self):
            return len(self._queue)

        def enqueue(self, server: tuple[str, int], left=False) -> None:
            """
            Adds a server to the queue, defaulting to the tail end (right).
            left=True adds the server to the front of the queue.
            Servers are only enqueued if they are not already in queue.
            """
            if server in self._queue:
                return
            if left:
                self._queue.appendleft(server)
                return
            self._queue.append(server)

        def dequeue(self) -> tuple[str, int]:
            """Gets the server at the front of the queue"""
            return self._queue.popleft()

    def __init__(self):

        super().__init__()

        # TODO make configurable
        self.SERVER_LIMIT = 1 + len(SC4MP_SERVERS) + 100

        try:
            servers_path = os.path.join(
                state.sc4mp_server_path, "_Database", "servers.json"
            )
            self.servers = load_json(servers_path)
        except Exception:
            self.servers = {}

        root_host, root_port = SC4MP_SERVERS[0]
        self.servers["root"] = {"host": root_host, "port": root_port}

        self.server_queue = self.ServerQueue(SC4MP_SERVERS.copy())

    def run(self):

        try:

            # Wait until the server starts
            while not state.sc4mp_server_running:
                time.sleep(SC4MP_DELAY)

            set_thread_name("SLThread", enumerate=False)

            # Run while the server is running
            while state.sc4mp_server_running:

                # Wait to ping the next server
                time.sleep(random.randint(1, 60))

                # Remove servers from the server list if the limit has been
                # reached (but never the default servers)
                while len(self.servers) > self.SERVER_LIMIT:
                    server_id = random.choice(list(self.servers.keys()))
                    candidate = self.servers[server_id]
                    address = (candidate["host"], candidate["port"])
                    if address not in SC4MP_SERVERS:
                        self.servers.pop(server_id)

                if len(self.server_queue) > 0 or len(self.servers) > 0:

                    # Get the next server
                    server = None
                    if len(self.server_queue) > 0:
                        server = self.server_queue.dequeue()
                    else:
                        server_id = random.choice(list(self.servers.keys()))
                        server_entry = self.servers.pop(server_id)
                        server = (server_entry["host"], server_entry["port"])
                    print(
                        "Synchronizing server list with " + server[0] + ":"
                        + str(server[1]) + "..."
                    )

                    # Ping the next server
                    try:

                        # Get the server's server id
                        server_id = self.request_server_id(server)

                        # Skip it if it matches the server id of this server
                        # (this also skips updating the database below)
                        own_server_id = state.sc4mp_config["INFO"]["server_id"]
                        if server_id == own_server_id:
                            # print(
                            #     "- \"" + server_id + "\" is our server_id!"
                            # )
                            continue

                        new_address = f"{server[0]}:{server[1]}"
                        new_entry = {"host": server[0], "port": server[1]}

                        # Resolve server id confilcts
                        if server_id in self.servers:
                            # print(
                            #     "- \"" + server_id + "\" already found in "
                            #     "our server list"
                            # )
                            old_entry = self.servers[server_id]
                            old_server = (old_entry["host"], old_entry["port"])
                            old_address = f"{old_server[0]}:{old_server[1]}"

                            if server != old_server:

                                print(
                                    f"[WARNING] The server at {new_address} "
                                    f"is using a server ID, \"{server_id}\", "
                                    f"which is already used by "
                                    f"{old_address}. Resolving server ID "
                                    f"conflict..."
                                )

                                try:
                                    old_server_id = \
                                        self.request_server_id(old_server)
                                except Exception:
                                    old_server_id = None

                                if old_server_id == server_id:
                                    print(
                                        f"[WARNING] - keeping the old server "
                                        f"({old_address}) and discarding the "
                                        f"new one ({new_address})."
                                    )
                                else:
                                    print(
                                        f"[WARNING] - keeping the new server "
                                        f"({new_address}) and discarding the "
                                        f"old one ({old_address})."
                                    )
                                    self.servers[server_id] = new_entry

                        else:
                            # print(
                            #     "- adding \"" + server_id + "\" to our "
                            #     "server list"
                            # )
                            self.servers[server_id] = new_entry

                        # Request to be added to the server's server list
                        # print(
                        #     "- requesting to be added to their server "
                        #     "list..."
                        # )
                        self.add_server(server)

                        # Get the server's server list
                        # print("- receiving their server list...")
                        self.server_list(server)

                        # print("- done.")

                    except Exception as e:

                        # show_error(e)

                        print(
                            f"[WARNING] Failed to synchronize server list "
                            f"with {server[0]}:{server[1]}! " + str(e)
                        )

                # Update database
                servers_path = os.path.join(
                    state.sc4mp_server_path, "_Database", "servers.json"
                )
                # report('Updating "' + servers_path + '"...')
                update_json(servers_path, self.servers)
                # print("- done.")

        except Exception as e:

            show_error(e)

    def create_socket(self, server):

        try:
            s = ClientSocket(server)
            set_headers(s)
            return s
        except Exception as e:
            raise ServerException("Server not found.") from e

    def request_server_id(self, server):

        SERVER_ID = 'server_id'

        with self.create_socket(server) as s:
            server_id = s.info().get(SERVER_ID)

        if server_id:
            return server_id
        else:
            raise ServerException(f"Headers missing {SERVER_ID!r}")

    def ping(self, server):

        try:
            with self.create_socket(server) as s:
                start = time.time()
                s.ping()
                end = time.time()
                return round(1000 * (end - start))
        except (NetworkException, OSError):
            return None

    def add_server(self, server):

        with self.create_socket(server) as s:
            s.add_server(
                host=state.sc4mp_config['NETWORK']['domain'],
                port=state.SC4MP_PORT
            )

    def server_list(self, server):

        with self.create_socket(server) as s:
            server_list = s.server_list()
            for host, port in server_list:
                self.server_queue.enqueue((host, port))
