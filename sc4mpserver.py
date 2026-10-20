"""SC4MP Server entry point: reads the command line arguments and starts
the server. The rest of the server is in the `server` package."""

import os
import subprocess
import sys
from argparse import ArgumentParser, Namespace
from datetime import datetime
from pathlib import Path

from core.util import (
    get_process_creation_time,
    is_frozen,
    is_windows,
    set_thread_name,
)
from server import state
from server.backups import restore
# SC4MP_GITHUB_REPO is not used here, but setup.py, publish.py and
# versioning.py import it (and SC4MP_VERSION) from this file.
from server.constants import (  # noqa: F401
    SC4MP_GITHUB_REPO,
    SC4MP_TITLE,
    SC4MP_VERSION,
)
from server.errors import ServerException, fatal_error
from server.logger import Logger
from server.server import Server
from server.utils import load_json, report, update_json


def main():
    """The main function."""

    try:

        # Set working directory
        exec_path = Path(sys.executable)
        exec_file = exec_path.name
        exec_dir = exec_path.parent
        if exec_file == "sc4mpserver.exe":
            os.chdir(exec_dir)

        # Parse arguments
        args = parse_args()

        # -k / --skip-update argument
        if args.skip_update is True:
            state.sc4mp_skip_update = True
        else:
            state.sc4mp_skip_update = False

        # -u / --force-update argument
        if args.force_update is True:
            state.sc4mp_force_update = True
        else:
            state.sc4mp_force_update = False

        # -s / --server-path argument
        if args.server_path:
            if not state.sc4mp_force_update:
                state.sc4mp_skip_update = True
            state.sc4mp_server_path = args.server_path
            os.makedirs(state.sc4mp_server_path, exist_ok=True)

        # -r / --restore argument
        if args.restore:
            restore(args.restore)
            return

        # -p / --prep argument
        if args.prep is True:
            state.sc4mp_nostart = True
        else:
            state.sc4mp_nostart = False

        # -v / --verbose argument
        if args.verbose:
            # TODO: use this flag to set logger level to debug once the logger PR is merged
            pass

        # If there's another server running from the same directory, kill it
        prevent_multiple()

        # Exit if --stop argument is provided
        if args.stop:
            return

        # Output
        sys.stdout = Logger()
        set_thread_name("Main", enumerate=False)

        # Title
        report(SC4MP_TITLE)

        # Server
        state.sc4mp_server = Server()
        if not state.sc4mp_nostart:
            state.sc4mp_server.run()

    except Exception as e:

        fatal_error(e)


def parse_args() -> Namespace:
    """Parse command line arguments"""

    parser = ArgumentParser(prog="SC4MP Server",
                            description="SimCity 4 Multiplayer Server")

    parser.add_argument("-s", "--server-path", help="specify server directory relative path")

    parser.add_argument("-t", "--stop", help="terminate the server currently running from the specified server path (Windows-only)", action="store_true")

    parser.add_argument("-k", "--skip-update", help="skip the update check at startup", action="store_true")

    parser.add_argument("-u", "--force-update", help="force update at startup (Windows-only)", action="store_true")

    parser.add_argument("-r", "--restore", help="restore the server to the specified backup")

    parser.add_argument("-v", "--verbose",
                        help="increase stdout/log verbosity",
                        action="store_true")

    parser.add_argument("-p", "--prep",
                        help="prep the server, but do not start",
                        action="store_true")

    parser.add_argument("--version", action="version",
                        version=f"{parser.prog} {SC4MP_VERSION}")

    return parser.parse_args()


def prevent_multiple():

    if is_windows() and is_frozen():

        try:

            DATETIME_FORMAT = "%Y%m%d%H%M%S"

            process_info_path = os.path.join(state.sc4mp_server_path, "process.json")

            if os.path.exists(process_info_path):

                process_info = load_json(process_info_path)

                if "pid" in process_info.keys() and "creation" in process_info.keys():

                    other_process_pid = process_info["pid"]
                    other_process_creation = process_info["creation"]

                    try:
                        o_p_c = datetime.strftime(get_process_creation_time(other_process_pid), DATETIME_FORMAT)
                    except Exception:
                        o_p_c = None

                    if other_process_creation == o_p_c:
                        # `TASKKILL` returns 128 if the process isn't running anymore (e.g. it exited but its process object still exists)
                        if subprocess.call(f"TASKKILL /F /PID {other_process_pid}", shell=True) not in (0, 128):
                            raise ServerException("`TASKKILL` failed to terminate the server process already running.")

            this_process_pid = os.getpid()
            this_process_creation = datetime.strftime(get_process_creation_time(this_process_pid), DATETIME_FORMAT)

            os.makedirs(state.sc4mp_server_path, exist_ok=True)

            update_json(process_info_path, {
                "pid": this_process_pid,
                    "creation": this_process_creation
            })

        except Exception as e:

            raise ServerException(f"Failed to terminate the server process already running.\n\n{e}") from e


def prep():
    return  # TODO move server init stuff here


def cleanup():
    return  # TODO


if __name__ == '__main__':
    main()
