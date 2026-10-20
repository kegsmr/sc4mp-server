"""DatabaseManager, a database that a background thread saves to disk."""

import threading as th
import time

from core.database import Database
from core.util import set_thread_name
from server import state
from server.constants import SC4MP_DELAY
from server.errors import fatal_error, show_error


class DatabaseManager(th.Thread, Database):

    def __init__(self, filename):

        th.Thread.__init__(self)
        Database.__init__(self, filename)

    def run(self):

        try:


            while not state.sc4mp_server_running:
                time.sleep(SC4MP_DELAY)

            set_thread_name("DbThread")

            while state.sc4mp_server_running:
                try:
                    time.sleep(SC4MP_DELAY)
                    self.update_json()
                except Exception as e:
                    show_error(e)

        except Exception as e:

            fatal_error(e)
