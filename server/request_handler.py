"""RequestHandler, which answers one client connection's requests."""

import hashlib
import os
import random
import string
import time
from datetime import datetime

from core.dbpf import SC4Savegame
from core.networking import BaseRequestHandler, ConnectionClosedException
from core.util import (
    sanitize_directory_name,
    set_thread_name,
    unformat_version,
    xor,
)
from server import state
from server.constants import SC4MP_DELAY, SC4MP_VERSION
from server.errors import ServerException, fatal_error, show_error
from server.files import (
    discard_bytes,
    get_file_table,
    receive_file,
    send_filestream,
)
from server.utils import file_md5, load_json, report


class RequestHandler(BaseRequestHandler):

    def __init__(self, c):

        super().__init__(c, private=state.sc4mp_config["SECURITY"]["private"])

    def run(self):

        try:


            set_thread_name("ReqThread")

            try:

                while state.sc4mp_server_running:

                    try:
                        command, headers = self.recv_request()
                    except ConnectionClosedException:
                        break

                    print(f"Request: {command!r}")
                    # print(f"Request: {command!r} {headers!r}")

                    self.handle_request()

            except ServerException as e:

                print(f"[WARNING] {e}")

            except Exception as e:

                show_error(e)

            state.sc4mp_request_threads -= 1

        except Exception as e:

            fatal_error(e)

    def authenticate(self):

        version = self.get_header('version', str)
        if unformat_version(version)[:2] < unformat_version(SC4MP_VERSION)[:2]:
            self.error("Incorrect version.")

        if state.sc4mp_config["SECURITY"]["password_enabled"]:
            password = self.get_header('password', str)
            if password != state.sc4mp_config["SECURITY"]["password"]:
                self.error("Incorrect password.")

        self.user_id = \
            self.authenticate_user(self.c, self.get_header('user_id', str))

    def authenticate_user(self, c, user_id):

        # Use a hashcode of the user id for extra security
        user_id = hashlib.sha256(user_id.encode()).hexdigest()[:32]

        # Get the ip
        user_ip = c.getpeername()[0]

        # Get clients database
        clients_data = state.sc4mp_clients_database_manager

        # Get data entry that matches ip
        client_entry = clients_data[user_ip]

        # Check if the client has exceeded the user limit
        if user_id not in client_entry["users"]:
            if (state.sc4mp_config["SECURITY"]["max_ip_users"] is None or len(client_entry["users"]) < state.sc4mp_config["SECURITY"]["max_ip_users"]):
                client_entry["users"].append(user_id)
            else:
                self.error("User limit exceeded.")

        # Get users database
        users_data = state.sc4mp_users_database_manager

        # Get data entry that matches user id or get & set to {}
        user_entry = users_data.setdefault(user_id, {})

        # Set default values if missing
        user_entry.setdefault("clients", [])
        user_entry.setdefault("mayors", [])
        user_entry.setdefault("ban", False)
        user_entry.setdefault("first_contact", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        # Close connection and throw error if the user is banned
        if (user_entry["ban"] or client_entry["ban"]):  # TODO check for client bans in server loop
            self.error("You are banned from this server.")

        # Log the time
        user_entry["last_contact"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Log the IP
        clients_entry = user_entry["clients"]
        if user_ip not in clients_entry:
            clients_entry.append(user_ip)

        # Return the user id
        return user_id

    def error(self, message='An error occurred.'):

        self.respond(error=message)

        raise ServerException(
            f"Error for {self.c.getpeername()[0]}: {message!r}"
        )

    def res_user_id(self):

        in_hash = self.get_header('hash', str)

        # Get database
        data = state.sc4mp_users_database_manager

        # Get the user_id that matches the hash
        found = False
        user_id = None
        for user_id in data:
            try:
                token = data[user_id]["token"]
                if hashlib.sha256((user_id + token).encode()).hexdigest() == in_hash:
                    found = True
                    break
            except Exception:
                pass

        # Send it if found, otherwise return failure
        if found:
            self.respond(status='success', user_id=user_id)
        else:
            self.respond(status='failure')

    def res_token(self):

        user_id = self.user_id

        token = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for i in range(32))

        # Get database
        data = state.sc4mp_users_database_manager

        # Get database entry for user
        key = user_id
        entry = data.get(key, {})
        if entry is None:
            entry = {}
        data[key] = entry

        # Set token in database entry
        entry["token"] = token

        # Send token
        self.respond(token=token)

    def res_plugins_table(self):

        self.respond()
        self.c.send_json(
            get_file_table(os.path.join(state.sc4mp_server_path, "Plugins"))
        )

    def res_plugins_data(self):

        self.respond()
        send_filestream(self.c, os.path.join(state.sc4mp_server_path, "Plugins"))

    def res_regions_data(self):

        if state.sc4mp_regions_manager.regions_modified:
            state.sc4mp_regions_manager.export_regions = True
            while state.sc4mp_regions_manager.export_regions:
                time.sleep(SC4MP_DELAY)
            time.sleep(SC4MP_DELAY * 2)

        self.respond()
        send_filestream(self.c, os.path.join(state.sc4mp_server_path, "_Temp", "outbound", "Regions"))

    def res_regions_table(self):

        self.respond()
        self.c.send_json(
            get_file_table(
                os.path.join(state.sc4mp_server_path, "_Temp", "outbound", "Regions")
            )
        )

    def res_save(self):

        c = self.c
        user_id = self.user_id

        self.respond()

        # Receive region name, file sizes
        region, file_sizes = c.recv_json()
        region = sanitize_directory_name(region)
        file_sizes = [int(file_size) for file_size in file_sizes]

        # Enforce max file count and file sizes
        error = None
        if not file_sizes:
            error = "No files."
        elif len(file_sizes) > 17:
            error = "Too many files."
        elif max(file_sizes) > 500_000_000:
            error = "File too large."

        if error is not None:
            discard_bytes(c, sum(file_sizes))
            self.respond(result=error)
            return

        # Set save id
        save_id = sanitize_directory_name(datetime.now().strftime("%Y%m%d%H%M%S") + "_" + user_id + "_" + os.urandom(4).hex())  # unique, even for pushes by the same user in the same second

        # Receive files
        count = 0
        for file_size in file_sizes:

            # Receive file
            path = os.path.join(state.sc4mp_server_path, "_Temp", "inbound", save_id, region)
            if not os.path.exists(path):
                os.makedirs(path)
            filename = os.path.join(path, str(count) + ".sc4")
            receive_file(c, filename, file_size)

            count += 1

        # Get path to save directory
        path = os.path.join(state.sc4mp_server_path, "_Temp", "inbound", save_id)

        # Get regions in save directory
        regions = os.listdir(path)

        # Only allow save pushes of one region
        if len(regions) > 1:
            self.respond(result="Too many regions.")
            return

        # Loop through regions. Should only loop once since save pushes of multiple regions are filtered out.
        for region in regions:

            # Get region path
            region_path = os.path.join(path, region)

            # Create DBPF objects for each file, and extract the region subfile from each DBPF
            savegames = []
            try:
                for filename in os.listdir(region_path):
                    filename = os.path.join(region_path, filename)
                    savegames.append(SC4Savegame(filename, error_callback=show_error))
                for savegame in savegames:
                    savegame.get_SC4ReadRegionalCity()
            except Exception as e:
                print(f"[WARNING] Invalid savegame: {e!r}")
                for savegame in savegames:
                    savegame.close()
                self.respond(result="Invalid savegame.")
                return

            # Filter out tiles that do not border every other tile
            report("Savegame filter 1", self)
            new_savegames = []
            for savegame in savegames:
                add = True
                savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
                savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
                savegameSizeX = savegame.SC4ReadRegionalCity["citySizeX"]
                savegameSizeY = savegame.SC4ReadRegionalCity["citySizeY"]
                for neighbor in savegames:
                    if neighbor == savegame:
                        continue
                    neighborX = neighbor.SC4ReadRegionalCity["tileXLocation"]
                    neighborY = neighbor.SC4ReadRegionalCity["tileYLocation"]
                    neighborSizeX = neighbor.SC4ReadRegionalCity["citySizeX"]
                    neighborSizeY = neighbor.SC4ReadRegionalCity["citySizeY"]
                    conditionX1 = (neighborX == savegameX - neighborSizeX)
                    conditionX2 = (neighborX == savegameX + savegameSizeX)
                    conditionY1 = (neighborY == savegameY - neighborSizeY)
                    conditionY2 = (neighborY == savegameY + savegameSizeY)
                    conditionX = xor(conditionX1, conditionX2) and ((neighborY + neighborSizeY > savegameY) or (neighborY < savegameY + savegameSizeY))
                    conditionY = xor(conditionY1, conditionY2) and ((neighborX + neighborSizeX > savegameX) or (neighborX < savegameX + savegameSizeX))
                    condition = xor(conditionX, conditionY)
                    if not condition:
                        add = False
                if add:
                    new_savegames.append(savegame)
                    report("YES (" + str(savegameX) + ", " + str(savegameY) + ")", self)
                else:
                    report("NO (" + str(savegameX) + ", " + str(savegameY) + ")", self)
            savegames = new_savegames

            # Filter out tiles which have identical date subfiles as their previous versions
            if len(savegames) > 1:
                report("Savegame filter 2", self)
                new_savegames = []
                for savegame in savegames:
                    savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
                    savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
                    coords = str(savegameX) + "_" + str(savegameY)
                    data = load_json(os.path.join(state.sc4mp_server_path, "Regions", region, "_Database", "region.json"))
                    if coords in data:
                        entry = data[coords] or {}
                        date_subfile_hashes = entry.get("date_subfile_hashes", [])
                        new_date_subfile_hash = file_md5(savegame.decompress_subfile("2990c1e5"))
                        if new_date_subfile_hash not in date_subfile_hashes:
                            new_savegames.append(savegame)
                            report("YES (" + str(savegameX) + ", " + str(savegameY) + ")", self)
                        else:
                            report("NO (" + str(savegameX) + ", " + str(savegameY) + ")", self)
                    else:
                        new_savegames.append(savegame)
                        report("YES (" + str(savegameX) + ", " + str(savegameY) + ")", self)
                    savegame = None
                savegames = new_savegames
            else:
                report("Skipping savegame filter 2", self)

            # If one savegame remains, pass it to the regions manager, otherwise report to the client that the save push is invalid
            if len(savegames) == 1:

                # Get the savegame
                savegame = savegames[0]

                # Send the task to the regions manager
                state.sc4mp_regions_manager.tasks.append((save_id, user_id, region, savegame))

                # Wait for the output
                while save_id not in state.sc4mp_regions_manager.outputs:
                    time.sleep(SC4MP_DELAY)

                # Send the output to the client
                self.respond(result=state.sc4mp_regions_manager.outputs[save_id])

            else:

                # Report to the client that the save push is invalid
                self.respond(result="Unpause the game, then retry.")

            # Delete savegame arrays to avoid file deletion errors
            savegames = None
            new_savegames = None

    def res_add_server(self):

        if state.sc4mp_config["NETWORK"]["discoverable"]:

            host = self.get_header('host', str) or self.c.getpeername()[0]
            port = self.get_header('port', int)

            server = (host, port)

            if len(state.sc4mp_server_list.server_queue) < state.sc4mp_server_list.SERVER_LIMIT:
                state.sc4mp_server_list.server_queue.enqueue(server, left=True)  # skip to the front of the queue

            self.respond(status='success')

        else:

            self.error("Server is not discoverable.")

    def res_server_list(self):

        if state.sc4mp_config["NETWORK"]["discoverable"]:
            self.respond()
        else:
            self.error("Server is not discoverable.")

        server_dict = state.sc4mp_server_list.servers.copy()

        servers = set()
        for server_info in server_dict.values():
            servers.add((server_info["host"], server_info["port"]))

        self.c.send_json(list(servers))

    def res_check_password(self):

        password = self.get_header('password', str)

        if password == state.sc4mp_config["SECURITY"]["password"]:
            status = 'success'
        else:
            status = 'failure'

        self.respond(status=status)

    def res_loading_background(self):

        background_image_filename = \
            os.path.join(state.sc4mp_server_path, "background.png")

        if os.path.exists(background_image_filename):
            data = open(background_image_filename, "rb").read()
            self.respond(size=len(data))
            self.c.sendall(data)
        else:
            self.error("Server has no loading background.")
