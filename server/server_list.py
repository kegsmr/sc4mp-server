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

    class ServerQueue:
        """
        Queue for server scanning that implements membership check before enqueuing.
        Can optionally enqueue to the front (left) of the queue.
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

        self.SERVER_LIMIT = 1 + len(SC4MP_SERVERS) + 100  # TODO make configurable

        try:
            self.servers = load_json(os.path.join(state.sc4mp_server_path, "_Database", "servers.json"))
        except Exception:
            self.servers = {}

        self.servers["root"] = {"host": SC4MP_SERVERS[0][0], "port": SC4MP_SERVERS[0][1]}

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

                # Remove servers from the server list if the limit has been reached
                while len(self.servers) > self.SERVER_LIMIT:
                    server_id = random.choice(list(self.servers.keys()))
                    if (self.servers[server_id]["host"], self.servers[server_id]["port"]) not in SC4MP_SERVERS:
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
                    print("Synchronizing server list with " + server[0] + ":" + str(server[1]) + "...")

                    # Ping the next server
                    try:

                        # Get the server's server id
                        server_id = self.request_server_id(server)

                        # Skip it if it matches the server id of this server
                        if server_id == state.sc4mp_config["INFO"]["server_id"]:
                            # print("- \"" + server_id + "\" is our server_id!")
                            continue

                        # Resolve server id confilcts
                        if server_id in self.servers:
                            # print("- \"" + server_id + "\" already found in our server list")
                            old_server = (self.servers[server_id]["host"], self.servers[server_id]["port"])

                            if server != old_server:

                                print(f"[WARNING] The server at {server[0]}:{server[1]} is using a server ID, \"{server_id}\", which is already used by {old_server[0]}:{old_server[1]}. Resolving server ID conflict...")

                                try:
                                    old_server_id = self.request_server_id(old_server)
                                except Exception:
                                    old_server_id = None

                                if old_server_id == server_id:
                                    print(f"[WARNING] - keeping the old server ({old_server[0]}:{old_server[1]}) and discarding the new one ({server[0]}:{server[1]}).")
                                else:
                                    print(f"[WARNING] - keeping the new server ({server[0]}:{server[1]}) and discarding the old one ({old_server[0]}:{old_server[1]}).")
                                    self.servers[server_id] = {"host": server[0], "port": server[1]}

                        else:
                            # print("- adding \"" + server_id + "\" to our server list")
                            self.servers[server_id] = {"host": server[0], "port": server[1]}

                        # Request to be added to the server's server list
                        # print("- requesting to be added to their server list...")
                        self.add_server(server)

                        # Get the server's server list
                        # print("- receiving their server list...")
                        self.server_list(server)

                        # print("- done.")

                    except Exception as e:

                        # show_error(e)

                        print(f"[WARNING] Failed to synchronize server list with {server[0]}:{server[1]}! " + str(e))

                # Update database
                # report('Updating "' + os.path.join(sc4mp_server_path, "_Database", "servers.json") + '"...')
                update_json(os.path.join(state.sc4mp_server_path, "_Database", "servers.json"), self.servers)
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
