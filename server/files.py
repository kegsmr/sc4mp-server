"""Packaging and exporting the plugins and regions folders, and sending and
receiving files over a connection."""

import os
import shutil
import time

from server import state
from server.constants import SC4MP_BUFFER_SIZE, SC4MP_DELAY
from server.errors import ServerException, show_error
from server.utils import load_json, report, update_json


def package_plugins_and_regions():

    report("Packaging plugins and regions...")

    report("- packaging plugins...")
    package("plugins")

    report("- packaging regions...")
    package("regions")

    # Imported here, not at the top, because server.regions imports
    # this module (a top-level import would be circular)
    from server.regions import RegionsManager

    # Regions manager
    state.sc4mp_regions_manager = RegionsManager()
    state.sc4mp_regions_manager.start()


def package(package_type):

    directory = None
    if package_type == "plugins":
        directory = "Plugins"
    elif package_type == "regions":
        directory = "Regions"

    target = os.path.join(state.sc4mp_server_path, directory)
    destination = os.path.join(state.sc4mp_server_path, "_Temp", "outbound", directory)

    if os.path.exists(destination):
        os.remove(destination)

    shutil.make_archive(destination, "zip", target)


def export(export_type):

    # Select directory name from input
    directory = None
    if export_type == "plugins":
        directory = "Plugins"
    elif export_type == "regions":
        directory = "Regions"

    # Set target and destination directories
    target = os.path.join(state.sc4mp_server_path, directory)
    destination = os.path.join(state.sc4mp_server_path, "_Temp", "outbound", directory)

    # Erase file table if exists
    if destination in state.sc4mp_filetables_manager.filetables.keys():
        state.sc4mp_filetables_manager.erase(destination)

    # TODO delete old abandoned savegames

    # Replace missing savegame files with the reset savegame file if it exists, and reset the claim
    try:
        if export_type == "regions":
            for region in os.listdir(target):
                if region.lower() == "downloads":
                    continue  # SC4 creates a `Downloads` folder that isn't a region
                if os.path.isdir(os.path.join(target, region)):
                    data_filename = os.path.join(target, region, "_Database", "region.json")
                    data = load_json(data_filename)
                    update_database = False
                    for entry in data.values():
                        if entry is not None:
                            filename = entry.get("filename", None)
                            if filename is not None:
                                filename = os.path.join(target, region, filename)
                                if not os.path.exists(filename):
                                    print(f"[WARNING] Savegame at \"{filename}\" is missing!")
                                    reset_filename = entry.get("reset_filename", None)
                                    if reset_filename is not None:
                                        reset_filename = os.path.join(target, region, reset_filename)
                                        if os.path.exists(reset_filename):
                                            print(f"[WARNING] - replacing with \"{reset_filename}\"...")
                                            shutil.copy(reset_filename, filename)
                                        else:
                                            print(f"[WARNING] - cannot replace with \"{reset_filename}\", since the file does not exist.")
                                    else:
                                        entry["filename"] = None
                                    print("[WARNING] - resetting claim...")
                                    entry["owner"] = None
                                    update_database = True
                    if update_database:
                        update_json(data_filename, data)
    except Exception as e:
        show_error(e)

    # Delete destination directory if it exists
    if os.path.exists(destination):
        shutil.rmtree(destination)

    # Create the parent directories if they do not yet exist
    # if (not os.path.exists(destination)):
    # os.makedirs(destination)

    # Copy recursively
    shutil.copytree(target, destination, ignore=shutil.ignore_patterns('_Backups'))  # , '_Database'))

    # Don't send the `Downloads` folder to clients, since it isn't a region
    if export_type == "regions":
        shutil.rmtree(os.path.join(destination, "Downloads"), ignore_errors=True)

    # Generate filetable
    state.sc4mp_filetables_manager.generate(destination)


def purge_directory(directory):
    """TODO

    Arguments:
            TODO

    Returns:
            TODO
    """
    for filename in os.listdir(directory):
        file_path = os.path.join(directory, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except PermissionError as e:
            raise ServerException('Failed to delete "' + file_path + '" because the file is being used by another process.') from e  # \n\n' + str(e)


def send_filestream(c, rootpath):

    file_table = get_file_table(rootpath)

    # Receive the filetable from the client and verify it
    ft = [tuple(item) for item in c.recv_json()]
    for item in ft:
        if not item in file_table:
            c.close()
            return
    filetable = ft

    # Loop through the filetable and send the respective data
    for _, size, relpath in filetable:
        with open(os.path.join(rootpath, relpath), "rb") as file:
            size_read = 0
            while True:
                size_remaining = size - size_read
                buffer_size = min(size_remaining, SC4MP_BUFFER_SIZE)
                data = file.read(buffer_size)
                if not data:
                    break
                size_read += len(data)
                c.sendall(data)


def get_file_table(rootpath):

    while state.sc4mp_server_running:
        try:
            filetable = state.sc4mp_filetables_manager.filetables[rootpath]
            break
        except KeyError:
            print("[WARNING] Waiting for file table to generate...")
            time.sleep(SC4MP_DELAY * 10)

    return filetable


def discard_bytes(c, size):
    """Receives and discards `size` bytes, eg. the files of a rejected save push, so the client gets to read the response."""

    size_read = 0
    while size_read < size:
        data = c.recv(min(size - size_read, SC4MP_BUFFER_SIZE))
        if not data:
            raise ServerException("Connection closed by client.")
        size_read += len(data)


def receive_file(c, filename, filesize):

    report("Receiving " + str(filesize) + " bytes...")
    report("writing to " + filename)

    if os.path.exists(filename):
        os.remove(filename)

    filesize_read = 0
    with open(filename, "wb") as f:
        while filesize_read < filesize:
            filesize_remaining = filesize - filesize_read
            buffersize = SC4MP_BUFFER_SIZE if filesize_remaining > SC4MP_BUFFER_SIZE else filesize_remaining
            bytes_read = c.recv(buffersize)
            if not bytes_read:
                raise ServerException("Connection closed by client.")
            f.write(bytes_read)
            filesize_read += len(bytes_read)
