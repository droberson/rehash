"""
help command.

Prints out the help menu at rehash> prompt

TODO: readline support for tab completion.
TODO: in-depth help for specific commands: help <command>
"""

from .commands import *

def cmd_help(sock, cmdline):
    maxlen = max([len(x[0]) for x in commandhelp])
    for item in commandhelp:
        print("%s - %s" % (item[0].ljust(maxlen), item[1]))
    prompt(sock)

commands.append(("help", cmd_help))
commandhelp.append(("help", "shows this help menu."))

