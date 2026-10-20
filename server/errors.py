"""The server's exception class and the functions that report errors."""

import traceback

from server import state


def show_error(e, no_ui=False):

    message = None
    if isinstance(e, str):
        message = e
    else:
        message = str(e)

    print("[ERROR] " + message + "\n\n" + traceback.format_exc())


def fatal_error(e):

    message = None
    if isinstance(e, str):
        message = e
    else:
        message = str(e)

    print("[FATAL] " + message + "\n\n" + traceback.format_exc())

    # if (sc4mp_ui != None):
    #     if (sc4mp_ui == True):
    #         tk.Tk().withdraw()
    #     messagebox.showerror(SC4MP_TITLE, message)

    state.sc4mp_server_running = False

    if state.sc4mp_system_tray_icon_manager:
        state.sc4mp_system_tray_icon_manager.status("Stopped", "A fatal error has occurred. Please check the logs at \"Documents\\SimCity 4\\SC4MP Server\\sc4mpserver.log\" for more details.")


class ServerException(Exception):

    def __init__(self, message, *args):

        super().__init__(args)
        self.message = message

    def __str__(self):

        return self.message
