"""BackupsManager, which backs up the server folder every few hours, and
restore(), which restores a backup."""

from __future__ import annotations

import json
import os
import shutil
import threading as th
import time
from datetime import datetime, timedelta
from pathlib import Path

from core.util import set_thread_name
from server import state
from server.constants import SC4MP_DELAY
from server.errors import ServerException, fatal_error, show_error
from server.utils import load_json, md5, report


def restore(filename):

    possible_paths = [
        os.path.join(state.sc4mp_server_path, "_Backups", filename),
        os.path.join(state.sc4mp_server_path, "_Backups", filename + ".json"),
        os.path.join(state.sc4mp_server_path, filename),
        os.path.join(state.sc4mp_server_path, filename + ".json"),
        filename,
        filename + ".json",
    ]
    for path in possible_paths:
        if not os.path.exists(path):
            continue
        else:
            if path[-5:] != ".json":
                raise ServerException("Backup file must be a \".json\" file.")
            print("Restoring backup at \"" + path + "\"")
            data = load_json(path)
            directory, filename = os.path.split(os.path.abspath(path))
            files_entry = data["files"]
            for original_filename, file_entry in files_entry.items():
                hashcode = file_entry["hashcode"]
                size = file_entry["size"]
                data_filename = os.path.join(directory, "data", hashcode + "_" + str(size))
                restore_filename = os.path.join(directory, "restores", filename[:-5], original_filename)
                print("Copying \"" + data_filename + "\" to \"" + restore_filename + "\"")
                restore_directory = os.path.split(restore_filename)[0]
                if not os.path.exists(restore_directory):
                    os.makedirs(restore_directory)
                shutil.copy(data_filename, restore_filename)
            print("- done.")
            return
    raise ServerException("File not found.")


class BackupsManager(th.Thread):

    def __init__(self):

        self.backup_dir = Path(state.sc4mp_server_path) / "_Backups"
        super().__init__()

    def run(self):

        try:


            set_thread_name("BakThread", enumerate=False)

            while not state.sc4mp_server_running:

                time.sleep(SC4MP_DELAY)

            while state.sc4mp_server_running:

                # Delay
                time.sleep(3600 * state.sc4mp_config["BACKUPS"]["server_backup_interval"])

                while state.sc4mp_server_running:

                    try:

                        # Create backup
                        self.backup()

                        # Break the loop if the backup was successful
                        break

                    except Exception as e:

                        # Report error
                        show_error(e)

                        # Wait before retrying backup
                        time.sleep(60)

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

    def backup(self):  # TODO stop backing up the backups subdirectory

        # Prune backups
        try:
            self.prune()
        except Exception as e:
            show_error("An error occurred while pruning backups.")

        # Report creating backups
        report("Creating backup...", self)

        # Loop through all files in server directory and append them to a list
        fullpaths = []
        for path, directories, files in os.walk(state.sc4mp_server_path):
            for file in files:
                if not os.path.abspath(os.path.join(state.sc4mp_server_path, "_Backups")) in os.path.abspath(path):
                    fullpaths.append(os.path.join(path, file))

        # Create a files entry for the backup dictionary
        files_entry = {}

        # Loop through fullpaths and backup the files and add them to the files entry
        for fullpath in fullpaths:
            hashcode = md5(fullpath)
            filesize = os.path.getsize(fullpath)
            directory = os.path.join(state.sc4mp_server_path, "_Backups", "data")
            if not os.path.exists(directory):
                os.makedirs(directory)
            filename = os.path.join(directory, hashcode + "_" + str(filesize))
            if not os.path.exists(filename) or hashcode != md5(filename) or filesize != os.path.getsize(filename):
                report('- copying "' + fullpath + '"...', self)
                if os.path.exists(filename):
                    os.remove(filename)
                shutil.copy(fullpath, filename)
            fullpath_entry = {}
            fullpath_entry["hashcode"] = hashcode
            fullpath_entry["size"] = filesize
            # fullpath_entry["backup_filename"] = filename
            files_entry[fullpath] = fullpath_entry

        # Create dictionary for backup and add the files entry
        backup_data = {}
        backup_data["files"] = files_entry

        # Update database
        backup_filename = os.path.join(state.sc4mp_server_path, "_Backups", datetime.now().strftime("%Y%m%d%H%M%S") + ".json")
        self.update_json(backup_filename, backup_data)

        # Report done
        report("- done.", self)

    def prune(self) -> None:
        """
        Prunes the backup data by first removing any json backup records
        that are older than the retention period, then comparing the backup
        files to the entries in the remaining json files.
        """
        report('Pruning backups...', self)
        max_server_backup_days = state.sc4mp_config["BACKUPS"]["max_server_backup_days"]

        if max_server_backup_days is not None:
            self.prune_backup_records(max_server_backup_days)

        self.prune_backup_data()

    def prune_backup_records(self, days: int) -> None:
        """Delete expired backup records"""

        cutoff = datetime.now() - timedelta(days=days)

        for backup in self.backup_dir.glob('*.json'):
            backup_date = datetime.strptime(backup.stem, "%Y%m%d%H%M%S")
            if backup_date < cutoff:
                backup.unlink()

    def prune_backup_data(self) -> None:
        """Delete unreferenced backup data"""

        # collect all backup references from json records
        referenced_files = self.get_referenced_files()

        # remove unreferenced backup files
        backup_file_dir = self.backup_dir / 'data'
        if backup_file_dir.exists():
            for file in [f for f in backup_file_dir.iterdir() if f.is_file()]:

                # parse hash and filesize from file name
                hashcode, size_str = file.stem.split('_')
                size = int(size_str)

                if (hashcode, size) not in referenced_files:
                    file.unlink()

    def get_referenced_files(self) -> set[tuple[str, int]]:
        """Return all referenced backup files as a set of tuples of (hashcode, size)"""
        # # types
        # FileDetail = TypedDict('FileDetail', {'hashcode': str, 'size': int})
        # BackupJSON = TypedDict('BackupJSON', {'files': "dict[str, FileDetail]"})

        referenced_files: set[tuple[str, int]] = set()

        for json_path in self.backup_dir.glob('*.json'):

            backup_json = load_json(json_path)

            for file_detail in backup_json['files'].values():
                hashcode = file_detail['hashcode']
                size = file_detail['size']
                referenced_files.add((hashcode, size))

        return referenced_files
