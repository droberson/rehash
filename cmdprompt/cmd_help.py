from .commands import *

def cmd_help(sock, cmdline):
    for item in commandhelp:
        print("%s - %s" % (item[0], item[1]))
    prompt(sock)

commands.append(("help", cmd_help))
commandhelp.append(("help", "shows this help menu."))

