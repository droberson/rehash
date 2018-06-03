"""
continue command.

This drops out of the rehash> prompt back to the shell session.
"""

from .commands import *


def cmd_continue(sock, cmdline):
    pass

commands.append(("continue", cmd_continue))
commandhelp.append(("continue", "exit rehash> prompt and return to session."))

