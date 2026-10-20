"""Small helpers used across the server: output, JSON files, hashes,
savegame data and socket headers."""

import hashlib
import json
import os
import struct
from datetime import datetime

from core.dbpf import SC4Savegame
from core.util import filter_non_alpha_numeric
from server import state
from server.constants import SC4MP_RESOURCES_PATH, SC4MP_VERSION


def get_sc4mp_path(filename):
    """TODO Gives the path of a given file in the SC4MP "resources"
    subdirectory

    Arguments:
        filename (str)

    Returns:
        TODO type: the path to the given file
    """
    return os.path.join(SC4MP_RESOURCES_PATH, filename)


def md5(filename):
    """TODO Creates the hashcode for a given file.

        filename (str)

    Returns:
        TODO type: hashcode
    """
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def file_md5(file):

    hash_md5 = hashlib.md5()
    for chunk in iter(lambda: file.read(4096), b""):
        hash_md5.update(chunk)
    return hash_md5.hexdigest()


def create_empty_json(filename):

    with open(filename, 'w') as file:
        data = {}
        file.seek(0)
        json.dump(data, file, indent=4)
        file.truncate()


def load_json(filename):
    """Returns data from a json file as a dictionary."""
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
            if data is None:
                return {}
            else:
                return data
    except FileNotFoundError:
        return {}


def set_savegame_data(entry, savegame: SC4Savegame):
    """TODO entry values"""

    # Get budget subfile
    savegame.get_cSC4BudgetSimulator()

    # No overwrite
    entry.setdefault("owner", None)
    entry.setdefault("modified", None)
    entry.setdefault("locked", False)
    filename = os.path.basename(os.path.normpath(savegame.filename))
    entry.setdefault("filename", filename)
    entry.setdefault("reset_filename", None)
    entry.setdefault("date_subfile_hashes", [])
    entry.setdefault("last_mayor_name", None)

    # Append
    date_subfile_hash = file_md5(savegame.decompress_subfile("2990c1e5"))
    date_subfile_hashes = entry["date_subfile_hashes"]
    if date_subfile_hash not in date_subfile_hashes:
        date_subfile_hashes.append(date_subfile_hash)

    # Overwrite
    city = savegame.SC4ReadRegionalCity
    entry["hashcode"] = md5(savegame.filename)
    entry["size"] = city["citySizeX"]
    entry["city_name"] = city["cityName"]
    entry["mayor_name"] = city["mayorName"]
    entry["gamemode"] = city["modeFlag"]
    entry["difficulty"] = city["starCount"]
    entry["mayor_rating"] = city["mayorRating"]
    entry["residential_population"] = city["residentialPopulation"]
    entry["commercial_population"] = city["commercialPopulation"]
    entry["industrial_population"] = city["industrialPopulation"]
    entry["population"] = (
        entry["residential_population"]
        + entry["commercial_population"]
        + entry["industrial_population"]
    )
    area = entry["size"] * entry["size"]
    entry["population_density"] = round(entry["population"] / area)
    entry["residential_population_density"] = round(
        entry["residential_population"] / area
    )
    entry["total_funds"] = savegame.cSC4BudgetSimulator["totalFunds"]

    # Log mayor name
    if state.sc4mp_server_running:
        owner = entry.get("owner", None)
        if owner is not None:
            mayor_name = entry.get("mayor_name", None)
            if mayor_name is not None:
                last_mayor_name = entry.get("last_mayor_name", None)
                if mayor_name != last_mayor_name:
                    users = state.sc4mp_users_database_manager
                    mayor_names = users[owner]["mayors"]
                    if mayor_name not in mayor_names:
                        mayor_names.append(mayor_name)


def update_json(filename, data):

    # Write to a temporary file first so a crash or error mid-write can't
    # truncate the original
    temp_filename = f"{filename}.tmp"
    with open(temp_filename, 'w') as file:
        json.dump(data, file, indent=4)
        file.flush()
        os.fsync(file.fileno())
    try:
        os.replace(temp_filename, filename)
    except PermissionError:
        # On Windows, the replace fails while another process or thread has
        # the file open, so fall back to writing in place
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
        os.unlink(temp_filename)


# TODO do this in the logger to make sure output prints correctly
def report(message, obj=None, msg_type="INFO", ):
    # color = '\033[94m '
    # output = datetime.now().strftime("[%H:%M:%S] [SC4MP")
    # obj = None
    # for item in inspect.stack():
    #     if (obj != None):
    #         break
    #     try:
    #         obj = item[0].f_locals["self"]
    #     except Exception:
    #         pass
    # if (obj != None):
    #     output += "/" + obj.__class__.__name__
    #     color = '\033[0m '
    # output+= "] [" + msg_type + "] " + message
    # if (msg_type=="WARNING"):
    #     color = '\033[93m '
    # elif (msg_type == "ERROR" or msg_type == "FATAL"):
    #     color = '\033[91m '
    # print(color + output)
    print("[" + msg_type + "] " + message)


def update_config_constants(config):
    """Copies a few config values to `state`. Called by Config.update()."""

    state.SC4MP_HOST = config['NETWORK']['host']
    state.SC4MP_PORT = config['NETWORK']['port']
    state.SC4MP_SERVER_ID = config['INFO']['server_id']
    state.SC4MP_SERVER_NAME = config['INFO']['server_name']
    state.SC4MP_SERVER_DESCRIPTION = config['INFO']['server_description']


def get_bitmap_dimensions(filename):
    """Returns the width and height of a bitmap file."""

    with open(filename, "rb") as file:
        data = file.read(26)

    width = struct.unpack_from("<i", data, 18)[0]
    # The height is negative for bitmaps stored top-down
    height = abs(struct.unpack_from("<i", data, 22)[0])

    return width, height


def set_savegame_filename(savegameX, savegameY, savegameCityName,
                          savegameMayorName, savegameModeFlag):

    prefix = f"({savegameX:0>{3}}-{savegameY:0>{3}})"

    if savegameModeFlag == 0:

        return f"{prefix} - (Empty).sc4"

    else:

        if savegameCityName:
            city_name = filter_non_alpha_numeric(savegameCityName)
            if len(city_name) < 1:
                city_name = "New City"
        else:
            city_name = "(Error)"

        if savegameMayorName:
            mayor_name = filter_non_alpha_numeric(savegameMayorName)
            if len(mayor_name) < 1:
                mayor_name = "Defacto"
        else:
            mayor_name = "(Error)"

        return f"{prefix} - {city_name} - {mayor_name}"[:252] + ".sc4"


def set_headers(s):

    # The socket adds these headers to every message it sends
    config = state.sc4mp_config
    return s.set_headers(
        server_id=config["INFO"]["server_id"],
        server_name=config["INFO"]["server_name"],
        server_description=config["INFO"]["server_description"],
        server_url=config["INFO"]["server_url"],
        server_version=SC4MP_VERSION,
        private=config["SECURITY"]["private"],
        password_enabled=config["SECURITY"]["password_enabled"],
        user_plugins_enabled=config["RULES"]["user_plugins"],
        claim_duration=config["RULES"]["claim_duration"],
        max_region_claims=config["RULES"]["max_region_claims"],
        godmode_filter=config["RULES"]["godmode_filter"],
        time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )
