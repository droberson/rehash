"""
exit command.

This closes the session and exits.
"""

import os

from .commands import *


def cmd_exit(sock, cmdline):
    sock.close()
    exit(os.EX_OK)

commands.append(("exit", cmd_exit))
commandhelp.append(("exit", "ends the session and exits the program"))

