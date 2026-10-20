"""Logger, which replaces stdout to add a timestamp, thread name, class name
and color to each line, and copies it to the log file."""

import inspect
import os
import sys
import threading as th
from datetime import datetime

from server import state
from server.constants import SC4MP_LOG_PATH


class Logger():
    """Replaces `sys.stdout`, so every `print()` goes through `write()`."""

    def __init__(self):

        self.terminal = sys.stdout
        if self.terminal is not None:
            # Characters the console can't show (eg. emoji on a cp1252
            # console) are printed as "?"
            self.terminal.reconfigure(errors="replace")
        if state.sc4mp_server_path == "_SC4MP":
            self.log = SC4MP_LOG_PATH
        else:
            self.log = os.path.join(state.sc4mp_server_path, SC4MP_LOG_PATH)
        if os.path.exists(self.log):
            os.remove(self.log)

    def write(self, message):

        output = message

        if message != "\n":

            # Timestamp
            timestamp = datetime.now().strftime("[%H:%M:%S] ")

            # Label: the thread name, then the class of the first caller
            # that is a method (the frames above this one are searched for a
            # `self` variable)
            label = "[SC4MP/" + th.current_thread().getName() + "] "
            for item in inspect.stack()[1:]:
                try:
                    class_name = item[0].f_locals["self"].__class__.__name__
                    label += "(" + class_name + ") "
                    break
                except Exception:
                    pass

            # Type and color
            msg_type = "[INFO] "
            color = '\033[90m '
            TYPES_COLORS = [
                ("[INFO] ", '\033[90m '),  # '\033[94m '
                ("[PROMPT]", '\033[01m '),
                ("[WARNING] ", '\033[93m '),
                ("[ERROR] ", '\033[91m '),
                ("[FATAL] ", '\033[91m ')
            ]
            for index in range(len(TYPES_COLORS)):
                current_type = TYPES_COLORS[index][0]
                current_color = TYPES_COLORS[index][1]
                if message[:len(current_type)] == current_type:
                    message = message[len(current_type):]
                    msg_type = current_type
                    color = current_color
                    break
            thread_name = th.current_thread().getName()
            if (thread_name == "Main" and msg_type == "[INFO] "):
                color = '\033[00m '

            # Assemble
            output = color + timestamp + label + msg_type + message

        # Print
        self.terminal.write(output)
        with open(self.log, "a", encoding='utf-8') as log:
            log.write(output)
            log.close()

    def flush(self):

        self.terminal.flush()
