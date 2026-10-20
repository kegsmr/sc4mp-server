"""FileTablesManager, which keeps the lists of files (with checksums and
sizes) that clients download."""

import os
import threading as th
import time
from pathlib import Path

from core.util import set_thread_name
from server import state
from server.constants import SC4MP_DELAY
from server.errors import fatal_error, show_error
from server.utils import md5


class FileTablesManager(th.Thread):

    def __init__(self):

        super().__init__()

        self.filetables = {}

    def run(self):

        try:

            while (not state.sc4mp_server_running):

                time.sleep(SC4MP_DELAY)

            set_thread_name("FtThread")

            while (state.sc4mp_server_running):

                try:

                    time.sleep(state.sc4mp_config["PERFORMANCE"]["filetable_update_interval"])
                    self.update()

                except Exception as e:

                    show_error(e)

        except Exception as e:

            fatal_error(e)

    def update(self):

        # Loop through all file tables
        for rootpath, filetable in self.filetables.items():

            # Loop through file table and check for missing files and files which have changed size (iterate over a copy since entries are removed)
            for entry in list(filetable):
                checksum, size, relpath = entry
                fullpath = os.path.join(rootpath, relpath)
                if not os.path.exists(fullpath):
                    filetable.remove(entry)
                    print(f"Removed deleted file \"{fullpath}\" from file table.")
                elif os.path.getsize(fullpath) != size:
                    filetable.remove(entry)
                    print(f"Removed old file \"{fullpath}\" from file table.")

            # Get all files in rootpath
            fullpaths = []
            for path, directories, files in os.walk(rootpath):
                for file in files:
                    fullpaths.append(os.path.join(path, file))

            # Add new files to the file table
            relpaths = [entry[2] for entry in filetable]
            for fullpath in fullpaths:
                relpath = Path(os.path.relpath(fullpath, rootpath)).as_posix()
                if not relpath in relpaths:
                    filetable.append((md5(fullpath), os.path.getsize(fullpath), relpath))
                    print(f"Added new file \"{fullpath}\" to file table.")

    def generate(self, rootpath):

        print(f"Generating file table for \"{rootpath}\"...")

        fullpaths = []
        for path, directories, files in os.walk(rootpath):
            for file in files:
                fullpaths.append(os.path.join(path, file))

        self.filetables[rootpath] = [(md5(fullpath), os.path.getsize(fullpath), Path(os.path.relpath(fullpath, rootpath)).as_posix()) for fullpath in fullpaths]

        # print(self.filetables[path])

        print("- done.")

    def erase(self, rootpath):

        print(f"Erasing file table for \"{rootpath}\"...")

        self.filetables.pop(rootpath)

        print("- done.")
