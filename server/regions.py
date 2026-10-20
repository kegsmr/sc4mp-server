"""RegionsManager, the thread that checks save pushes and copies accepted
savegames into the regions."""

import json
import os
import random
import shutil
import threading as th
import time
from datetime import datetime, timedelta

from core.util import set_thread_name
from server import state
from server.constants import SC4MP_DELAY
from server.errors import fatal_error, show_error
from server.files import export
from server.utils import (
    get_bitmap_dimensions,
    report,
    set_savegame_data,
    set_savegame_filename,
)


class RegionsManager(th.Thread):

    def __init__(self):

        super().__init__()

        self.regions_modified = False
        self.export_regions = False
        self.tasks = []
        self.outputs = {}
        # self.lastmtime = self.get_mtime()

    def run(self):

        try:


            while not state.sc4mp_server_running:

                time.sleep(SC4MP_DELAY)

            set_thread_name("RgnThread", enumerate=False)

            while state.sc4mp_server_running:

                try:

                    # Mark regions as modified if modification time changes
                    # mtime = self.get_mtime()
                    # if mtime != self.lastmtime:
                    # self.lastmtime = mtime
                    # self.regions_modified = True

                    # Export regions if requested, otherwise check for new tasks
                    if self.export_regions:

                        report("Exporting regions as requested...", self)

                        export("regions")

                        report("- done.", self)

                        self.regions_modified = False
                        self.export_regions = False

                    else:

                        # Check for the next task
                        if len(self.tasks) > 0:

                            # Get the next task
                            task = self.tasks.pop(0)

                            # Read values from tuple
                            save_id, user_id, region, savegame = task

                            report('Processing task "' + save_id + '"...', self)

                            # Another layer of exception handling so that the request handler isn't waiting around in the event of an error
                            try:

                                # Get values from savegame
                                filename = savegame.filename
                                savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
                                savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
                                savegameSizeX = savegame.SC4ReadRegionalCity["citySizeX"]
                                savegameSizeY = savegame.SC4ReadRegionalCity["citySizeY"]
                                savegameModeFlag = savegame.SC4ReadRegionalCity["modeFlag"]
                                savegameCityName = savegame.SC4ReadRegionalCity["cityName"]
                                savegameMayorName = savegame.SC4ReadRegionalCity["mayorName"]

                                # Set "coords" variable. Used as a key in the region database and also for the name of the new save file
                                coords = f'{savegameX}_{savegameY}'

                                # Get region database
                                data_filename = os.path.join(state.sc4mp_server_path, "Regions", region, "_Database", "region.json")
                                data = self.load_json(data_filename)

                                # Get city entry or get & set as empty dict if key does not exist
                                entry = data.setdefault(coords, {})

                                # Filter out cities that don't match the region configuration
                                if entry is None:
                                    self.outputs[save_id] = "Invalid city location."
                                    entry = {}

                                # Filter out claims on locked tiles
                                if entry.get("locked", False):
                                    self.outputs[save_id] = "Tile is locked."

                                # Filter out cities outside the bounds of the region (each pixel of `config.bmp` is one tile)
                                try:
                                    region_width, region_height = get_bitmap_dimensions(os.path.join(state.sc4mp_server_path, "Regions", region, "config.bmp"))
                                except Exception as e:
                                    show_error(f"Unable to read the region configuration for \"{region}\", skipping bounds check.\n\n{e}")
                                    region_width, region_height = None, None
                                if region_width is not None and (savegameX + savegameSizeX > region_width or savegameY + savegameSizeY > region_height):
                                    self.outputs[save_id] = "Invalid city location."

                                # Filter out godmode savegames if required
                                if state.sc4mp_config["RULES"]["godmode_filter"]:
                                    if savegameModeFlag == 0:
                                        self.outputs[save_id] = "You must establish a city before claiming a tile."

                                # Filter out cities of the wrong size
                                if "size" in entry:
                                    if (savegameSizeX != savegameSizeY or savegameSizeX != entry["size"]):
                                        self.outputs[save_id] = "Invalid city size."

                                # Filter out claims on tiles with unexpired claims of other users
                                reclaimed = False
                                if "owner" in entry:
                                    owner = entry["owner"]
                                    if (owner is not None and owner != user_id):
                                        if state.sc4mp_config["RULES"]["claim_duration"] is None:
                                            self.outputs[save_id] = "City already claimed."
                                        else:
                                            expires = datetime.strptime(entry["modified"], "%Y-%m-%d %H:%M:%S") + timedelta(days=state.sc4mp_config["RULES"]["claim_duration"])
                                            if expires > datetime.now():
                                                self.outputs[save_id] = "City already claimed."
                                        reclaimed = True

                                # Filter out cliams of users who have exhausted their region claims
                                if ("owner" not in entry or entry["owner"] != user_id):
                                    if state.sc4mp_config["RULES"]["max_region_claims"] is not None:
                                        claims = len(list(filter(lambda x: x is not None and x.get("owner") == user_id, data.values())))
                                        if claims >= state.sc4mp_config["RULES"]["max_region_claims"]:
                                            self.outputs[save_id] = "Claim limit reached in this region."

                                # Filter out claims of users who have exhausted their total claims
                                # TODO

                                # Proceed if save push has not been filtered out
                                if save_id not in self.outputs:

                                    # Delete previous save file if it exists
                                    if "filename" in entry and entry["filename"] is not None:
                                        previous_filename = os.path.join(state.sc4mp_server_path, "Regions", region, entry["filename"])
                                        if os.path.exists(previous_filename):
                                            os.remove(previous_filename)

                                    # Set new filename
                                    new_filename = set_savegame_filename(savegameX, savegameY, savegameCityName, savegameMayorName, savegameModeFlag)
                                    new_filename_oldscheme = f"{coords}.sc4"

                                    # Copy save file from temporary directory to regions directory (use old naming scheme if new one causes an error)
                                    destination_directory = os.path.join(state.sc4mp_server_path, "Regions", region)
                                    try:
                                        destination = os.path.join(destination_directory, new_filename)
                                        if os.path.exists(destination):
                                            os.remove(destination)
                                        shutil.copy(filename, destination)
                                    except Exception:
                                        destination = os.path.join(destination_directory, new_filename_oldscheme)
                                        if os.path.exists(destination):
                                            os.remove(destination)
                                        shutil.copy(filename, destination)

                                    # Copy save file from temporary directory to backup directory
                                    backup_directory = os.path.join(state.sc4mp_server_path, "Regions", region, "_Backups", coords)
                                    if not os.path.exists(backup_directory):
                                        os.makedirs(backup_directory)
                                    while (state.sc4mp_config["BACKUPS"]["max_savegame_backups"] is not None and len(os.listdir(backup_directory)) > state.sc4mp_config["BACKUPS"]["max_savegame_backups"]):
                                        delete_filename = random.choice(os.listdir(backup_directory))
                                        if delete_filename == "reset.sc4":
                                            continue
                                        os.remove(os.path.join(backup_directory, delete_filename))
                                    destination = os.path.join(backup_directory, datetime.now().strftime("%Y%m%d%H%M%S") + ".sc4")
                                    shutil.copy(filename, destination)
                                    # TODO delete old backups

                                    # Set entry values
                                    entry["filename"] = new_filename
                                    entry["owner"] = user_id
                                    entry["modified"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                    entry["reclaimed"] = reclaimed or entry.get("reclaimed", False)
                                    if reclaimed:
                                        entry["last_mayor_name"] = entry.get("mayor_name", None)
                                    set_savegame_data(entry, savegame)

                                    # Update database
                                    self.update_json(data_filename, data)

                                    # Mark regions as modified
                                    self.regions_modified = True

                                    # Report success
                                    self.outputs[save_id] = "ok"

                            except Exception as e:

                                # Report an error to the request handler
                                self.outputs[save_id] = "Unexpected server-side error."

                                # Raise the exception so that it appears in the server's output
                                raise e

                            finally:

                                # Close the savegame so its temporary file can be deleted (Windows can't delete open files)
                                savegame.close()

                            report("- done.", self)

                        else:

                            # Clean up inbound temporary files and outputs
                            try:
                                path = os.path.join(state.sc4mp_server_path, "_Temp", "inbound")
                                for directory in os.listdir(path):
                                    if directory in self.outputs:

                                        shutil.rmtree(os.path.join(path, directory))

                                        # sleep to allow RequestHandler.save() time to check for success #TODO better solution needed, but this works for now
                                        time.sleep(2 * SC4MP_DELAY)

                                        self.outputs.pop(directory)

                            except Exception as e:
                                pass

                            time.sleep(SC4MP_DELAY)

                except Exception as e:

                    show_error(e)

                    time.sleep(5)

        except Exception as e:

            fatal_error(e)

    def load_json(self, filename):

        try:
            with open(filename, 'r') as file:
                return json.load(file)
        except Exception:
            return {}

    def update_json(self, filename, data):

        # Write to a temporary file first so a crash or error mid-write can't truncate the original
        temp_filename = f"{filename}.tmp"
        with open(temp_filename, 'w') as file:
            json.dump(data, file, indent=4)
            file.flush()
            os.fsync(file.fileno())
        try:
            os.replace(temp_filename, filename)
        except PermissionError:
            # On Windows, the replace fails while another process or thread has the file open, so fall back to writing in place
            with open(filename, 'w') as file:
                json.dump(data, file, indent=4)
            os.unlink(temp_filename)

    def get_mtime(self):

        return os.path.getmtime(os.path.join(state.sc4mp_server_path, "Regions"))
