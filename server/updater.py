"""UpdaterMixin, the part of Server that downloads and installs updates."""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

from core.util import set_thread_name, unformat_version
from server import state
from server.constants import (
    SC4MP_BUFFER_SIZE,
    SC4MP_GITHUB_REPO,
    SC4MP_VERSION,
)
from server.errors import ServerException, show_error
from server.files import purge_directory


# The name of the Windows build's executable
PROCESS_NAME = "sc4mpserver.exe"


class UpdaterMixin:
    """Update check for the Server class."""

    def check_updates(self):

        if not state.sc4mp_skip_update:

            print("Checking for updates...")

            try:

                # Get the path of the executable file which is currently
                # running
                exec_path = Path(sys.executable)
                exec_file = exec_path.name
                exec_dir = exec_path.parent

                # Only update if running a Windows distribution
                if state.sc4mp_force_update or exec_file == PROCESS_NAME:

                    # Get latest release info
                    url = (
                        f"https://api.github.com/repos/{SC4MP_GITHUB_REPO}"
                        f"/releases/latest"
                    )
                    try:
                        with urllib.request.urlopen(url, timeout=10) as file:
                            latest_release_info = json.load(file)
                    except urllib.error.URLError as e:
                        raise ServerException(
                            "GitHub API call timed out."
                        ) from e

                    # Download the update if the version doesn't match
                    if state.sc4mp_force_update:
                        update_needed = True
                    else:
                        tag_name = latest_release_info["tag_name"]
                        latest_version = unformat_version(tag_name)
                        current_version = unformat_version(SC4MP_VERSION)
                        update_needed = latest_version > current_version

                    if update_needed:

                        self.install_update(
                            latest_release_info, exec_file, exec_dir
                        )

                        # Stop the system tray icon, since its thread would
                        # otherwise keep the process running after
                        # `sys.exit()`
                        if state.sc4mp_system_tray_icon_manager:
                            state.sc4mp_system_tray_icon_manager.icon.stop()

                        # Exit when complete
                        sys.exit()

            except Exception as e:

                # Show error silently and continue as usual
                show_error(
                    f"An error occurred while updating.\n\n{e}", no_ui=True
                )

    def install_update(self, latest_release_info, exec_file, exec_dir):
        """Downloads the installer of the latest release and writes and starts
        `updater.bat`, which waits for this process to exit, runs the
        installer and starts the server again."""

        try:

            set_thread_name("UpdtThread", enumerate=False)

            # Function to write to console and update ui
            def report(message):
                print(message)

            # Change working directory to the one where the executable can be
            # found
            if exec_file == PROCESS_NAME:
                os.chdir(exec_dir)

            # Delete updater.bat
            if os.path.exists("updater.bat"):
                os.unlink("updater.bat")

            # Purge update directory
            try:
                if os.path.exists("update"):
                    purge_directory(Path("update"))
            except Exception:
                pass

            # Delete uninstaller if exists
            try:
                for filename in ["unins000.dat", "unins000.exe"]:
                    if os.path.exists(filename):
                        os.unlink(filename)
            except Exception:
                pass

            # Report
            report("Downloading update...")

            # Get download URL
            download_url = None
            for asset in latest_release_info["assets"]:
                if asset["name"].startswith("sc4mp-server-installer-windows"):
                    download_url = asset["browser_download_url"]
                    destination = os.path.join("update", asset["name"])
                    break

            # Raise an exception if the download URL was not found
            if download_url is None:
                raise ServerException(
                    "The correct release asset was not found."
                )

            # Prepare destination
            os.makedirs("update", exist_ok=True)
            if os.path.exists(destination):
                os.unlink(destination)

            # Download file
            headers = urllib.request.urlopen(download_url).headers
            download_size = int(headers["Content-Length"])
            with urllib.request.urlopen(download_url) as rfile:
                with open(destination, "wb") as wfile:
                    download_size_downloaded = 0
                    while download_size_downloaded < download_size:
                        bytes_read = rfile.read(SC4MP_BUFFER_SIZE)
                        download_size_downloaded += len(bytes_read)
                        wfile.write(bytes_read)

            # Convert destination to path object
            destination = Path(destination)

            # Report installing update
            report("Installing update...")

            # Create `updater.bat``
            args = sys.argv
            args.pop(0)
            if "-u" in args:
                args.remove("-u")
            if "--force-update" in args:
                args.remove("--force-update")
            if "-k" not in args and "--skip-update" not in args:
                # So a failed install relaunches the current version instead
                # of updating again in a loop
                args.append("-k")
            with open("updater.bat", "w") as batch_file:
                batch_file.writelines([
                    "@echo off\n",
                    f"cd /d \"{os.getcwd()}\"\n",
                    "echo Waiting for the server to exit...\n",
                    ":wait\n",
                    # The installer can't replace files the server still has
                    # open
                    f"tasklist /fi \"PID eq {os.getpid()}\" "
                    f"| find \"{os.getpid()}\" "
                    f">nul && (timeout /t 1 /nobreak >nul & goto wait)\n",
                    "echo Running installer...\n",
                    f"cd {destination.parent}\n",
                    f"{destination.stem} /dir=\"{os.getcwd()}\" /verysilent\n",
                    "cd ..\n",
                    "echo Relaunching server...\n",
                    f"{PROCESS_NAME} {subprocess.list2cmdline(args)}\n"
                ])

            # Start installer in very silent mode and exit
            subprocess.Popen(["updater.bat"])

        except Exception as e:

            show_error(
                f"An error occurred in the update thread.\n\n{e}", no_ui=True
            )
