"""StartupMixin, the part of Server that prepares the config, folders,
databases, regions, backups and server list before it starts listening."""

from __future__ import annotations

import os
import shutil
import socket
import sys
import time
from pathlib import Path

from core.config import Config
from core.dbpf import SC4Savegame
from core.util import is_frozen, is_windows
from server import state
from server.backups import BackupsManager
from server.constants import (
    SC4MP_CONFIG_DEFAULTS,
    SC4MP_DELAY,
    SC4MP_TITLE,
)
from server.database_manager import DatabaseManager
from server.errors import ServerException, show_error
from server.files import export, purge_directory
from server.filetables import FileTablesManager
from server.regions import RegionsManager
from server.server_list import ServerList
from server.tray import (
    SystemTrayIconManager,
    sc4mp_has_pil,
    sc4mp_has_pystray,
)
from server.utils import (
    create_empty_json,
    get_sc4mp_path,
    load_json,
    report,
    set_savegame_data,
    set_savegame_filename,
    update_config_constants,
    update_json,
)


class StartupMixin:
    """Startup steps for the Server class."""

    def create_subdirectories(self):

        report("Creating subdirectories...")

        directories = ["_Backups", "_Database", "_Temp", "Plugins", "Regions"]

        for directory in directories:
            new_directory = os.path.join(state.sc4mp_server_path, directory)
            if not os.path.exists(new_directory):
                try:
                    os.makedirs(new_directory)
                    if (directory == "Plugins" or directory == "Regions"):
                        shutil.unpack_archive(get_sc4mp_path(directory + ".zip"), new_directory)
                except Exception as e:
                    show_error(e)
                    # report("Failed to create " + directory + " subdirectory.", None, "WARNING")
                    # report('(this may have been printed by error, check your sc4mp_server_path subdirectory)', None, "WARNING")

        # Create helper batch files on Windows
        try:

            exec_path = Path(sys.executable)
            exec_file = exec_path.name
            exec_dir = exec_path.parent

            path = exec_dir if state.sc4mp_server_path == "_SC4MP" else state.sc4mp_server_path

            if exec_file == "sc4mpserver.exe":

                with open(os.path.join(path, "logs.bat"), "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                            (f"title {SC4MP_TITLE}\n" if state.sc4mp_server_path == "_SC4MP" else f"title {SC4MP_TITLE} - {state.sc4mp_server_path}\n"),
                            "PowerShell -NoProfile -ExecutionPolicy Bypass -Command \"gc sc4mpserver.log -wait -tail 1000\"\n",
                    ])

                with open(os.path.join(path, "run.bat"), "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                            f"cd /d \"{exec_dir}\"\n",
                            f"sc4mpserver.exe -s \"{state.sc4mp_server_path}\"\n",
                    ])

                with open(os.path.join(path, "start.bat"), "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                            f"cd /d \"{exec_dir}\"\n",
                            f"start \"\" sc4mpserver.exe -s \"{state.sc4mp_server_path}\"\n",
                    ])

                with open(os.path.join(path, "stop.bat"), "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                            f"cd /d \"{exec_dir}\"\n",
                            f"sc4mpserver.exe -s \"{state.sc4mp_server_path}\" --stop\n",
                    ])

                with open(os.path.join(path, "prep.bat"), "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                            f"cd /d \"{exec_dir}\"\n",
                            f"sc4mpserver.exe -s \"{state.sc4mp_server_path}\" --prep\n",
                    ])

                with open(os.path.join(path, "restore.bat"), "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                            f"cd /d \"{exec_dir}\"\n",
                            "set /p backup=\"Enter a backup to restore...\"\n",
                            f"sc4mpserver.exe -s \"{state.sc4mp_server_path}\" --restore %backup%\n",
                            "pause\n",
                    ])

                if state.sc4mp_server_path == "_SC4MP":

                    with open(os.path.join(path, "new.bat"), "w") as batch_file:
                        batch_file.writelines([
                            "@echo off\n",
                                f"cd /d \"{exec_dir}\"\n",
                                "set /p name=\"Enter the name of the new server configuration...\"\n",
                                f"sc4mpserver.exe -s \"{state.sc4mp_server_path}\" -s %name% --prep\n",
                                f"C:\Windows\explorer.exe \"{exec_dir}\\%name%\"\n"
                        ])

                    with open(os.path.join(path, "update.bat"), "w") as batch_file:
                        batch_file.writelines([
                            "@echo off\n",
                                f"cd /d \"{exec_dir}\"\n",
                                f"sc4mpserver.exe -s \"{state.sc4mp_server_path}\" -u\n",
                        ])

        except Exception as e:

            show_error(f"Failed to create helper batch files.\n\n{e}")

    def load_config(self):

        state.SC4MP_CONFIG_PATH = os.path.join(state.sc4mp_server_path, "serverconfig.ini")

        report("Loading config...")

        state.sc4mp_config = Config(state.SC4MP_CONFIG_PATH, SC4MP_CONFIG_DEFAULTS, error_callback=show_error, update_constants_callback=update_config_constants)

        # System tray icon
        if is_windows() and is_frozen() and state.sc4mp_config["UI"]['enabled'] and sc4mp_has_pystray and sc4mp_has_pil:
            state.sc4mp_system_tray_icon_manager = SystemTrayIconManager()
            state.sc4mp_system_tray_icon_manager.start()
            while not state.sc4mp_system_tray_icon_manager.icon.visible:
                time.sleep(SC4MP_DELAY)
            state.sc4mp_system_tray_icon_manager.status("Preparing", "Running in the background. Click on the system tray icon to manage your sever.")
        else:
            state.sc4mp_system_tray_icon_manager = None

    def prep_database(self):

        report("Preparing database...")

        # Database directory
        database_directory = os.path.join(state.sc4mp_server_path, "_Database")

        # Users database
        filename = os.path.join(database_directory, "users.json")
        if not os.path.exists(filename):
            create_empty_json(filename)

        # Clients database
        filename = os.path.join(database_directory, "clients.json")
        if not os.path.exists(filename):
            create_empty_json(filename)

        # Get region directory names
        regions = []
        regions_directory = os.path.join(state.sc4mp_server_path, "Regions")
        items = os.listdir(regions_directory)
        for item in items:
            if item.lower() == "downloads":
                continue  # SC4 creates a `Downloads` folder that isn't a region
            path = os.path.join(regions_directory, item)
            if not os.path.isfile(path):
                regions.append(item)

        # Create databases for each region
        for region in regions:

            # Region directory
            region_directory = os.path.join(regions_directory, region)

            # Create `region.ini` file if not present
            region_ini_path = os.path.join(region_directory, "region.ini")
            if not os.path.exists(region_ini_path):
                print(f"[WARNING] Region \"{region}\" is missing a configuration file. Creating...")
                with open(region_ini_path, "w") as file:
                    file.write(f"[Regional Settings]\nName = {region}\nTerrain type = 0\nWater Min = 60\nWater Max = 100\n")

            # Create subdirectories in region directory
            region_subdirectories = ["_Database", "_Backups"]
            for region_subdirectory in region_subdirectories:
                directory = os.path.join(region_directory, region_subdirectory)
                if not os.path.exists(directory):
                    os.makedirs(directory)

            # Get database
            filename = os.path.join(region_directory, "_Database", "region.json")
            data = None
            try:
                data = load_json(filename)
            except Exception:
                data = {}

            # Get savegame paths
            savegame_paths = []
            items = os.listdir(region_directory)
            for item in items:
                path = os.path.join(region_directory, item)
                if (os.path.isfile(path) and path[-4:] == ".sc4"):
                    savegame_paths.append(path)

            # Open savegames as DBPF objects
            savegames: list[SC4Savegame] = []
            for savegame_path in savegame_paths:
                savegames.append(SC4Savegame(savegame_path, error_callback=show_error))

            # Get the region subfile of each DBPF object and update the database
            for savegame in savegames:

                # Get region, budget subfiles
                savegame.get_SC4ReadRegionalCity()

                # Get values from region subfile
                savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
                savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
                savegameSize = savegame.SC4ReadRegionalCity["citySizeX"]
                savegameCityName = savegame.SC4ReadRegionalCity["cityName"]
                savegameMayorName = savegame.SC4ReadRegionalCity["mayorName"]
                savegameModeFlag = savegame.SC4ReadRegionalCity["modeFlag"]

                # Get md5 hashcode of date subfile
                # savegame_date_subfile_hash = file_md5(savegame.decompress_subfile("2990c1e5"))

                # Get dictionary for savegame data
                coords = str(savegameX) + "_" + str(savegameY)
                entry = data.get(coords, {})
                if entry is None:
                    entry = {}
                data[coords] = entry

                # Create reset savegame file if needed
                if ("reset_filename" not in entry.keys()) or ((entry["reset_filename"] is not None) and (not os.path.exists(os.path.join(region_directory, entry["reset_filename"])))):
                    reset_directory = os.path.join("_Backups", coords)
                    os.makedirs(os.path.join(region_directory, reset_directory), exist_ok=True)
                    reset_filename = os.path.join(reset_directory, "reset.sc4")
                    if not os.path.exists(os.path.join(region_directory, reset_filename)):
                        shutil.copy(savegame.filename, os.path.join(region_directory, reset_filename))
                    entry["reset_filename"] = reset_filename

                # Set entry values
                set_savegame_data(entry, savegame)

                # Reserve tiles which the savegame occupies
                for offsetX in range(savegameSize):
                    x = savegameX + offsetX
                    for offsetY in range(savegameSize):
                        y = savegameY + offsetY
                        data.setdefault(str(x) + "_" + str(y), None)

                # Close DBPF file
                savegame.close()

                # Rename savegame file to match correct format
                new_filename = set_savegame_filename(savegameX, savegameY, savegameCityName, savegameMayorName, savegameModeFlag)
                if entry["filename"] is not None and entry["filename"] != new_filename:
                    print(f"- renaming \"{entry['filename']}\" to \"{new_filename}\"...")
                    try:
                        os.rename(os.path.join(region_directory, entry["filename"]), os.path.join(region_directory, new_filename))
                        entry["filename"] = new_filename
                    except Exception as e:
                        show_error(e)

            # Cleanup DBPF objects to avoid errors when attempting to delete save files
            savegames = None

            update_json(filename, data)

        if state.sc4mp_nostart:
            return

        # Users database manager
        state.sc4mp_users_database_manager = DatabaseManager(os.path.join(state.sc4mp_server_path, "_Database", "users.json"))
        state.sc4mp_users_database_manager.start()

        # Clients database manager
        state.sc4mp_clients_database_manager = DatabaseManager(os.path.join(state.sc4mp_server_path, "_Database", "clients.json"))
        state.sc4mp_clients_database_manager.start()

    def clear_temp(self):

        report("Clearing temporary files...")

        try:
            purge_directory(os.path.join(state.sc4mp_server_path, "_Temp"))
        except Exception as e:
            show_error(e)

    def prep_regions(self):

        if state.sc4mp_nostart:
            return

        report("Preparing regions...")

        export("regions")

        # Regions manager
        state.sc4mp_regions_manager = RegionsManager()
        state.sc4mp_regions_manager.start()

    def prep_backups(self):

        report("Preparing backups...")

        # Backups manager
        state.sc4mp_backups_manager = BackupsManager()
        if state.sc4mp_config["BACKUPS"]["backup_server_on_startup"]:
            state.sc4mp_backups_manager.backup()
        if not state.sc4mp_nostart:
            state.sc4mp_backups_manager.start()

    def prep_filetables(self):

        if not state.sc4mp_nostart:

            report("Preparing plugins...")  # report("Preparing file tables...")

            state.sc4mp_filetables_manager = FileTablesManager()

            state.sc4mp_filetables_manager.generate(os.path.join(state.sc4mp_server_path, "Plugins"))

            state.sc4mp_filetables_manager.start()

    def prep_server_list(self):

        if state.sc4mp_nostart:
            return

        if not state.sc4mp_config["NETWORK"]["discoverable"]:
            return

        report("Preparing server list...")

        state.sc4mp_server_list = ServerList()
        state.sc4mp_server_list.start()

    def prep_upnp(self):

        if state.sc4mp_config['NETWORK']['upnp']:

            print("Preparing UPnP port...")

            if not sc4mp_has_upnpclient:
                raise ServerException("UPnP requires the `upnpclient` module. Install the module or disable UPnP in `serverconfig.ini`, then restart the server.")

            port = state.sc4mp_config['NETWORK']['port']

            try:

                open_upnp_port(port, "TCP", "Created by SimCity 4 Multiplayer Project Server.")

            except Exception as e:

                raise ServerException(f"An error occurred while opening a port with UPnP. Disable UPnP in `serverconfig.ini`, forward port {port} manually, then restart the server.\n\n{e}") from e


def open_upnp_port(port, protocol="TCP", description="Port Forwarding via UPnP"):

    def get_gateway():

        devices = upnpclient.discover()

        print([device for device in devices])

        for device in devices:
            print(device.services)
            for service in device.services:
                if "WANIPConnection" in service.service_type or "WANPPPConnection" in service.service_type:
                    return device

        raise ServerException("No UPnP-enabled gateway found.")

    gateway = get_gateway()
    address = socket.gethostbyname(socket.gethostname())

    if address == "127.0.0.1":
        raise ServerException("Unable to determine LAN IP address.")

    for mapping in gateway.WANIPConnection.GetPortMapping():
        if mapping['NewExternalPort'] == str(port) and mapping['NewProtocol'] == protocol:
            print(f"Port {port} ({protocol}) is already mapped to {mapping['NewInternalClient']}.")
            return

    print(f"Opening port {port} ({protocol}) on \"{gateway.friendly_name}\"...")

    gateway.AddPortMapping(
        NewRemoteHost="",
        NewExternalPort=port,
        NewProtocol=protocol,
        NewInternalPort=port,
        NewInternalClient=address,
        NewEnabled=1,
        NewPortMappingDescription=description,
        NewLeaseDuration=0,
    )
