import os
import platform
import shutil
import struct
import subprocess  # noqa: F401 (for the commented-out pip install below)
import sys
from datetime import datetime

if sys.version_info[:2] != (3, 8):
    raise RuntimeError(
        f"Unsupported Python version: {sys.version}. Please use Python 3.8."
    )

# subprocess.run(
#     [sys.executable, "-m", "pip", "install", "-r", "requirements.txt"]
# )

import PyInstaller.__main__ as pyinstaller
from pyinstaller_versionfile import create_versionfile

import sc4mpserver
import core.util as utils

TITLE = "SC4MP Server"
NAME = "sc4mpserver.exe"
VERSION = (
    sc4mpserver.SC4MP_VERSION + "."
    + datetime.now().strftime("%Y%m%d%H%M%S")
)
PUBLISHER = "SimCity 4 Multiplayer Project"
DESCRIPTION = "Multiplayer gameserver for SimCity 4"
LICENSE = "MIT-0"
DIST = "dist" + str(8 * struct.calcsize("P"))


def main():

    # Update readme & installer version
    utils.update_readme_version("Readme.html", sc4mpserver.SC4MP_VERSION)
    utils.update_inno_setup_version("setup.iss", sc4mpserver.SC4MP_VERSION)

    # Update server list
    print("Updating server list...")
    try:
        utils.update_server_list()
    except Exception as e:
        print(f"- failed to update server list {e}!")

    # Make distribution directory if it does not yet exist
    print(f"Preparing distribution directory at \"{DIST}\"")
    if not os.path.exists(DIST):
        os.makedirs(DIST)

    # Purge the distribution directory
    for item in os.listdir(DIST):
        item = os.path.join(DIST, item)
        if (os.path.isfile(item)):
            os.remove(item)
        else:
            shutil.rmtree(item)

    # Create version file
    print("Creating version file...")
    create_versionfile(
        output_file="version.rc",
        version=VERSION,
        company_name=PUBLISHER,
        file_description=TITLE,
        internal_name=TITLE,
        legal_copyright=LICENSE,
        original_filename=NAME,
        product_name=TITLE,
    )

    # Run setup
    print("Running setup...")
    pyinstaller.run([
        "sc4mpserver.py",
        "--specpath",
        f"{os.path.join('temp', 'spec')}",
        "--distpath",
        "dist",
        "--workpath",
        f"{os.path.join('temp', 'build')}",
        "--onedir",
        "--contents-directory",
        "resources",
        "--noconfirm",
        "--noupx",
        "--console",
        "--hide-console",
        "hide-early",
        "-i",
        f"{os.path.abspath(os.path.join('resources', 'icon.ico'))}",
        "--version-file",
        f"{os.path.abspath('version.rc')}",
        "--exclude=numpy",
        "--exclude=cryptography",
    ])

    # Copy binary files to distribution directory
    shutil.copytree(
        os.path.join("dist", "sc4mpserver"), DIST, dirs_exist_ok=True
    )

    # Copy extra files to distribution directory
    print(f'Copying extra files to "{DIST}"...')
    shutil.copytree(
        "resources", os.path.join(DIST, "resources"), dirs_exist_ok=True
    )
    shutil.copy("License.txt", DIST)
    shutil.copy("Readme.html", DIST)

    # Create a zip archive of the distribution
    bits = str(8 * struct.calcsize("P"))
    archive_name = (
        "sc4mp-server-" + platform.system().lower() + "-" + bits
        + "-v" + VERSION
    )
    destination = os.path.join(os.path.join("builds", archive_name))
    print('Creating zip archive of "' + DIST + '" at "' + destination + '"')
    shutil.make_archive(destination, "zip", DIST)


if __name__ == "__main__":
    main()
