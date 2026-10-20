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
                    # New plugins and regions folders start with the default
                    # content from the resources folder
                    if (directory == "Plugins" or directory == "Regions"):
                        archive_path = get_sc4mp_path(directory + ".zip")
                        shutil.unpack_archive(archive_path, new_directory)
                except Exception as e:
                    show_error(e)
                    # report(
                    #     "Failed to create " + directory + " subdirectory.",
                    #     None, "WARNING"
                    # )
                    # report(
                    #     '(this may have been printed by error, check your '
                    #     'sc4mp_server_path subdirectory)', None, "WARNING"
                    # )

        # Create helper batch files on Windows
        self.create_helper_batch_files()

    def create_helper_batch_files(self):
        """Writes .bat files that run, stop, update, etc. this server. Only
        done when running the Windows build (sc4mpserver.exe)."""

        try:

            exec_path = Path(sys.executable)
            exec_file = exec_path.name
            exec_dir = exec_path.parent

            server_path = state.sc4mp_server_path

            # The default server's files go next to the executable
            if server_path == "_SC4MP":
                path = exec_dir
            else:
                path = server_path

            if exec_file == "sc4mpserver.exe":

                if server_path == "_SC4MP":
                    title_line = f"title {SC4MP_TITLE}\n"
                else:
                    title_line = f"title {SC4MP_TITLE} - {server_path}\n"

                with open(os.path.join(path, "logs.bat"), "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                        title_line,
                        "PowerShell -NoProfile -ExecutionPolicy Bypass "
                        "-Command \"gc sc4mpserver.log -wait -tail 1000\"\n",
                    ])

                with open(os.path.join(path, "run.bat"), "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                        f"cd /d \"{exec_dir}\"\n",
                        f"sc4mpserver.exe -s \"{server_path}\"\n",
                    ])

                with open(os.path.join(path, "start.bat"), "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                        f"cd /d \"{exec_dir}\"\n",
                        f"start \"\" sc4mpserver.exe -s \"{server_path}\"\n",
                    ])

                with open(os.path.join(path, "stop.bat"), "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                        f"cd /d \"{exec_dir}\"\n",
                        f"sc4mpserver.exe -s \"{server_path}\" --stop\n",
                    ])

                with open(os.path.join(path, "prep.bat"), "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                        f"cd /d \"{exec_dir}\"\n",
                        f"sc4mpserver.exe -s \"{server_path}\" --prep\n",
                    ])

                restore_path = os.path.join(path, "restore.bat")
                with open(restore_path, "w") as batch_file:
                    batch_file.writelines([
                        "@echo off\n",
                        f"cd /d \"{exec_dir}\"\n",
                        "set /p backup=\"Enter a backup to restore...\"\n",
                        f"sc4mpserver.exe -s \"{server_path}\" "
                        f"--restore %backup%\n",
                        "pause\n",
                    ])

                if server_path == "_SC4MP":

                    new_path = os.path.join(path, "new.bat")
                    with open(new_path, "w") as batch_file:
                        batch_file.writelines([
                            "@echo off\n",
                            f"cd /d \"{exec_dir}\"\n",
                            "set /p name=\"Enter the name of the new server "
                            "configuration...\"\n",
                            f"sc4mpserver.exe -s \"{server_path}\" -s %name% "
                            f"--prep\n",
                            f"C:\\Windows\\explorer.exe "
                            f"\"{exec_dir}\\%name%\"\n"
                        ])

                    update_path = os.path.join(path, "update.bat")
                    with open(update_path, "w") as batch_file:
                        batch_file.writelines([
                            "@echo off\n",
                            f"cd /d \"{exec_dir}\"\n",
                            f"sc4mpserver.exe -s \"{server_path}\" -u\n",
                        ])

        except Exception as e:

            show_error(f"Failed to create helper batch files.\n\n{e}")

    def load_config(self):

        state.SC4MP_CONFIG_PATH = os.path.join(
            state.sc4mp_server_path, "serverconfig.ini"
        )

        report("Loading config...")

        state.sc4mp_config = Config(
            state.SC4MP_CONFIG_PATH,
            SC4MP_CONFIG_DEFAULTS,
            error_callback=show_error,
            update_constants_callback=update_config_constants
        )

        # System tray icon (Windows build only, and only if the optional
        # modules are installed)
        if (is_windows() and is_frozen()
                and state.sc4mp_config["UI"]['enabled']
                and sc4mp_has_pystray and sc4mp_has_pil):
            state.sc4mp_system_tray_icon_manager = SystemTrayIconManager()
            state.sc4mp_system_tray_icon_manager.start()
            while not state.sc4mp_system_tray_icon_manager.icon.visible:
                time.sleep(SC4MP_DELAY)
            state.sc4mp_system_tray_icon_manager.status(
                "Preparing",
                "Running in the background. Click on the system tray icon to "
                "manage your sever."
            )
        else:
            state.sc4mp_system_tray_icon_manager = None

        # global SC4MP_HOST
        # global SC4MP_PORT
        # global SC4MP_SERVER_ID
        # global SC4MP_SERVER_NAME
        # global SC4MP_SERVER_DESCRIPTION
        #
        # report("Loading config...")
        #
        # config_path = os.path.join(sc4mp_server_path, "serverconfig.ini")
        #
        # try:
        #
        #     config = configparser.RawConfigParser()
        #     config.read(config_path)
        #
        #     SC4MP_HOST = config.get('server', "host")
        #     SC4MP_PORT = int(config.get('server', 'port'))
        #     SC4MP_SERVER_ID = config.get('server', "server_id")
        #     SC4MP_SERVER_NAME = config.get('server', "server_name")
        #     SC4MP_SERVER_DESCRIPTION = \
        #         config.get('server', "server_description")
        #
        # except Exception:
        #
        #     config.remove_section('server')
        #     config.add_section('server')
        #     config.set('server', 'host', default_host)
        #     config.set('server', 'port', default_port)
        #     config.set('server', 'server_id', default_server_id)
        #     config.set('server', 'server_name', default_server_name)
        #     config.set(
        #         'server', 'server_description', default_server_description
        #     )
        #
        #     with open(config_path, 'wt') as config_file:
        #         config.write(config_file)
        #
        #     SC4MP_HOST = default_host
        #     SC4MP_PORT = default_port
        #     SC4MP_SERVER_ID = default_server_id
        #     SC4MP_SERVER_NAME = default_server_name
        #     SC4MP_SERVER_DESCRIPTION = default_server_description

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
            # SC4 creates a `Downloads` folder that isn't a region
            if item.lower() == "downloads":
                continue
            path = os.path.join(regions_directory, item)
            if not os.path.isfile(path):
                regions.append(item)

        # Create databases for each region
        for region in regions:

            # Region directory
            region_directory = os.path.join(regions_directory, region)

            self.prep_region_database(region, region_directory)

        if state.sc4mp_nostart:
            return

        # Users database manager
        users_path = os.path.join(database_directory, "users.json")
        state.sc4mp_users_database_manager = DatabaseManager(users_path)
        state.sc4mp_users_database_manager.start()

        # Clients database manager
        clients_path = os.path.join(database_directory, "clients.json")
        state.sc4mp_clients_database_manager = DatabaseManager(clients_path)
        state.sc4mp_clients_database_manager.start()

    def prep_region_database(self, region, region_directory):
        """Updates a region's database from its savegames, makes the reset
        savegames and renames the savegames to the standard format."""

        # Create `region.ini` file if not present
        region_ini_path = os.path.join(region_directory, "region.ini")
        if not os.path.exists(region_ini_path):
            print(
                f"[WARNING] Region \"{region}\" is missing a configuration "
                f"file. Creating..."
            )
            with open(region_ini_path, "w") as file:
                file.write(
                    f"[Regional Settings]\n"
                    f"Name = {region}\n"
                    f"Terrain type = 0\n"
                    f"Water Min = 60\n"
                    f"Water Max = 100\n"
                )

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
            savegame = SC4Savegame(savegame_path, error_callback=show_error)
            savegames.append(savegame)

        # Get the region subfile of each DBPF object and update the database
        for savegame in savegames:

            # Get region, budget subfiles
            savegame.get_SC4ReadRegionalCity()

            # Get values from region subfile
            city = savegame.SC4ReadRegionalCity
            savegameX = city["tileXLocation"]
            savegameY = city["tileYLocation"]
            savegameSize = city["citySizeX"]
            savegameCityName = city["cityName"]
            savegameMayorName = city["mayorName"]
            savegameModeFlag = city["modeFlag"]

            # Get md5 hashcode of date subfile
            # savegame_date_subfile_hash = \
            #     file_md5(savegame.decompress_subfile("2990c1e5"))

            # Get dictionary for savegame data
            coords = str(savegameX) + "_" + str(savegameY)
            entry = data.get(coords, {})
            if entry is None:
                entry = {}
            data[coords] = entry

            # Create reset savegame file if needed. A reset savegame is
            # what the tile goes back to if its savegame goes missing. A
            # `reset_filename` of None means the tile has no reset savegame.
            if "reset_filename" not in entry.keys():
                needs_reset_file = True
            elif entry["reset_filename"] is None:
                needs_reset_file = False
            else:
                reset_path = os.path.join(
                    region_directory, entry["reset_filename"]
                )
                needs_reset_file = not os.path.exists(reset_path)
            if needs_reset_file:
                reset_directory = os.path.join("_Backups", coords)
                os.makedirs(
                    os.path.join(region_directory, reset_directory),
                    exist_ok=True
                )
                reset_filename = os.path.join(reset_directory, "reset.sc4")
                reset_path = os.path.join(region_directory, reset_filename)
                if not os.path.exists(reset_path):
                    shutil.copy(savegame.filename, reset_path)
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
            new_filename = set_savegame_filename(
                savegameX, savegameY, savegameCityName, savegameMayorName,
                savegameModeFlag
            )
            old_filename = entry["filename"]
            if old_filename is not None and old_filename != new_filename:
                print(
                    f"- renaming \"{old_filename}\" to \"{new_filename}\"..."
                )
                try:
                    os.rename(
                        os.path.join(region_directory, old_filename),
                        os.path.join(region_directory, new_filename)
                    )
                    entry["filename"] = new_filename
                except Exception as e:
                    show_error(e)

        # Cleanup DBPF objects to avoid errors when attempting to delete save
        # files
        savegames = None

        update_json(filename, data)

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

            # report("Preparing file tables...")
            report("Preparing plugins...")

            state.sc4mp_filetables_manager = FileTablesManager()

            plugins_path = os.path.join(state.sc4mp_server_path, "Plugins")
            state.sc4mp_filetables_manager.generate(plugins_path)

            state.sc4mp_filetables_manager.start()

    def prep_server_list(self):

        if state.sc4mp_nostart:
            return

        if not state.sc4mp_config["NETWORK"]["discoverable"]:
            return

        report("Preparing server list...")

        state.sc4mp_server_list = ServerList()
        state.sc4mp_server_list.start()

    # Not used yet: the call in Server.__init__ is commented out, and
    # `sc4mp_has_upnpclient` and `upnpclient` are not defined anywhere.
    def prep_upnp(self):

        if state.sc4mp_config['NETWORK']['upnp']:

            print("Preparing UPnP port...")

            if not sc4mp_has_upnpclient:  # noqa: F821
                raise ServerException(
                    "UPnP requires the `upnpclient` module. Install the "
                    "module or disable UPnP in `serverconfig.ini`, then "
                    "restart the server."
                )

            port = state.sc4mp_config['NETWORK']['port']

            try:

                open_upnp_port(
                    port, "TCP",
                    "Created by SimCity 4 Multiplayer Project Server."
                )

            except Exception as e:

                raise ServerException(
                    f"An error occurred while opening a port with UPnP. "
                    f"Disable UPnP in `serverconfig.ini`, forward port {port} "
                    f"manually, then restart the server.\n\n{e}"
                ) from e


# Not used yet (see `prep_upnp()`)
def open_upnp_port(port, protocol="TCP",
                   description="Port Forwarding via UPnP"):

    def get_gateway():

        devices = upnpclient.discover()  # noqa: F821

        print([device for device in devices])

        for device in devices:
            print(device.services)
            for service in device.services:
                service_type = service.service_type
                if ("WANIPConnection" in service_type
                        or "WANPPPConnection" in service_type):
                    return device

        raise ServerException("No UPnP-enabled gateway found.")

    gateway = get_gateway()
    address = socket.gethostbyname(socket.gethostname())

    if address == "127.0.0.1":
        raise ServerException("Unable to determine LAN IP address.")

    for mapping in gateway.WANIPConnection.GetPortMapping():
        if (mapping['NewExternalPort'] == str(port)
                and mapping['NewProtocol'] == protocol):
            internal_client = mapping['NewInternalClient']
            print(
                f"Port {port} ({protocol}) is already mapped to "
                f"{internal_client}."
            )
            return

    print(
        f"Opening port {port} ({protocol}) on \"{gateway.friendly_name}\"..."
    )

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
