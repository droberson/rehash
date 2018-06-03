'''
This is useless. Just a simple example of adding a command to the prompt.
'''
from .commands import *


def cmd_uname(sock, cmdline):
    print("cmdline=%s" % cmdline)
    uname = "uname -a" + "\n"
    print("uname=%s" % uname.encode())
    sock.send(uname.encode())

commands.append(("uname", cmd_uname))
commandhelp.append(("uname", "executes uname -a on a system"))
