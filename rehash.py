#!/usr/bin/env python3

""" rehash.py -- Netcat-like hacking harness.
      by Daniel Roberson @dmfroberson                   April/2018

    TODO: named ports. ex: ./rehash.py localhost ssh
    TODO: option to log outfile in pcap format?
"""

import os
import sys
import socket
import random
import select
import argparse

from network_common import *


VERSION = "1.0"


class Settings(object):
    """ Settings Object -- Stores application settings and methods to
                        -- manipulate them.
    """
    __config = {
        "broadcast" : False,
        "command" : "",
        "crlf" : False,
        "dns" : True,
        "exec" : None,
        "family" : None,
        "fast" : False,
        "interval" : 0,
        "ip" : "0.0.0.0",
        "ipv4" : False,
        "ipv6" : False,
        "keepalive" : False,
        "listen" : False,
        "logfile" : None,
        "outfile" : None,
        "localport" : None,
        "ports" : [],
        "randomize" : False,
        "resolved" : None,
        "socktype" : socket.SOCK_STREAM,
        "source" : None,
        "telnet" : False,
        "tos" : None,
        "udp" : False,
        "verbose" : False,
        "wait" : 0,
        "zero" : False,
    }

    __settings = [
        "broadcast",
        "command",
        "crlf",
        "dns",
        "exec",
        "family",
        "fast",
        "interval",
        "ip",
        "ipv4",
        "ipv6",
        "keepalive",
        "listen",
        "outfile",
        "localport",
        "ports",
        "randomize",
        "resolved",
        "socktype",
        "source",
        "telnet",
        "tos",
        "udp",
        "verbose",
        "wait",
        "zero",
    ]

    @staticmethod
    def get(name):
        """ Settings.get() -- Retrieve a configuration setting.

        Args:
            name (str) - Name of configuration setting.

        Returns:
            Contents of configuration setting.
        """
        return Settings.__config[name]

    @staticmethod
    def set(name, value):
        """ Settings.set() -- Apply a configuration setting.

        Args:
            name (str) - Name of configuration setting.
            value      - Value to apply to configuration setting.

        Returns:
            Nothing.
        """
        if name in Settings.__settings:
            Settings.__config[name] = value
        else:
            raise NameError("Not a valid setting for set() method: %s" % name)


def fatal(msg):
    """ fatal() -- Prints a message to stderr and exits with EX_USAGE.

    Args:
        msg (str) - Message to display prior to exiting.

    Returns:
        Nothing.
    """
    print(msg, file=sys.stderr)
    exit(os.EX_USAGE)


def parse_cli():
    """ parse_cli() -- Parse CLI arguments and perform sanity checks.

    Args:
        None

    Returns:
        Nothing
    """
    description = \
        "rehash version " + VERSION + " by Daniel Roberson @dmfroberson"
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument(
        "-4",
        "--ipv4",
        action="store_true",
        help="IPv4 mode")

    parser.add_argument(
        "-6",
        "--ipv6",
        action="store_true",
        help="IPv6 mode")

    parser.add_argument(
        "-b",
        "--broadcast",
        action="store_true",
        default=False,
        help="Allow broadcasts")

    parser.add_argument(
        "-c",
        "--command",
        default=None,
        help="Shell commands to exec after connect. Passed to /bin/sh -c")

    parser.add_argument(
        "-C",
        "--crlf",
        action="store_true",
        default=False,
        help="Send CRLF as line ending")

    parser.add_argument(
        "-e",
        "--exec",
        default=None,
        help="Program to execute after connection is established. ex: /bin/sh")

    parser.add_argument(
        "-F",
        "--fast",
        action="store_true",
        default=False,
        help="Use ports from /etc/services")

    parser.add_argument(
        "-i",
        "--interval",
        default=0,
        help="Delay interval for lines sent or ports scanned")

    parser.add_argument(
        "-k",
        "--keepalive",
        action="store_true",
        default=False,
        help="Keep socket alive")

    parser.add_argument(
        "-l",
        "--listen",
        action="store_true",
        default=False,
        help="Listen mode")

    parser.add_argument(
        "-n",
        "--nodns",
        action="store_true",
        default=False,
        help="Skip DNS resolution")

    parser.add_argument(
        "-o",
        "--outfile",
        default=None,
        help="Location of hexdump output of traffic")

    parser.add_argument(
        "-p",
        "--localport",
        default=None,
        help="Local port number")

    parser.add_argument(
        "-r",
        "--randomize",
        action="store_true",
        default=False,
        help="Randomize port numbers")

    parser.add_argument(
        "-s",
        "--source",
        default=None,
        help="Source IP address")

    parser.add_argument(
        "-t",
        "--telnet",
        action="store_true",
        default=False,
        help="Answer TELNET negotiation")

    parser.add_argument(
        "-T",
        "--tos",
        default=None,
        help="Type of Service")

    parser.add_argument(
        "-u",
        "--udp",
        action="store_true",
        default=False,
        help="UDP mode")

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Verbose output")

    parser.add_argument(
        "-w",
        "--wait",
        default=0,
        help="Timeout (in seconds) for connects and final net reads")

    parser.add_argument(
        "-z",
        "--zero",
        action="store_true",
        default=False,
        help="Zero IO mode (for scanning)")

    # Positional Arguments
    parser.add_argument(
        "host",
        action="store",
        nargs="?",
        help="Host to connect to")

    parser.add_argument(
        "ports",
        action="store",
        nargs="?",
        help="Port or range of ports. ex: 1-1024,8080")

    args = parser.parse_args()

    # Apply settings and check sanity of supplied CLI arguments.

    ## This should be before most things
    Settings.set("dns", True if args.nodns is False else False)

    ## Simple True/False flags here
    Settings.set("ipv4", args.ipv4)
    Settings.set("ipv6", args.ipv6)
    Settings.set("broadcast", args.broadcast)
    Settings.set("crlf", args.crlf)
    Settings.set("fast", args.fast)
    Settings.set("keepalive", args.keepalive)
    Settings.set("listen", args.listen)
    Settings.set("randomize", args.randomize)
    Settings.set("telnet", args.telnet)
    Settings.set("udp", args.udp)
    Settings.set("verbose", args.verbose)
    Settings.set("zero", args.zero)

    ## Make sure IPv4 and IPv6 aren't both specified. Default to IPv4.
    if args.ipv4 and args.ipv6:
        parser.print_help(sys.stderr)
        fatal("[-] Specified IPv4 and IPv6")
    if not args.ipv4 and not args.ipv6:
        args.ipv4 = True
    if args.ipv4:
        Settings.set("family", socket.AF_INET)
    if args.ipv6:
        Settings.set("family", socket.AF_INET6)

    ## Make sure source address is valid
    ## TODO: bind() or similar check to make sure this host is valid
    if args.source:
        if valid_ip_address(args.source):
            Settings.set("source", args.source)
        elif Settings.get("dns"):
            tmp = hostname_to_ip(args.source)
            if tmp:
                Settings.set("source", tmp)
            else:
                fatal("[-] Invalid hostname: %s" % args.source)
        else:
            fatal("[-] DNS resolution is disabled and hostname provided")

    ## Toggle UDP mode
    if Settings.get("udp") is True:
        Settings.set("socktype", socket.SOCK_DGRAM)

    ## Fast mode
    if Settings.get("fast") is True:
        protocol = protocol_from_socktype(Settings.get("socktype"))
        if protocol:
            Settings.set("ports", portlist_from_services(protocol))
        else:
            fatal("[-] Invalid socktype")

    ## Deal with --command and --exec
    if args.command and args.exec:
        fatal("[-] -c and -e set.")
    if args.command:
        # TODO validate this. commands are passed to /bin/sh -c
        Settings.set("command", args.command)
    if args.exec:
        # TODO validate this binary exists and permissions are correct
        Settings.set("exec", args.exec)

	## Output file.
    if args.outfile:
        # TODO verify file exists or can be written
        # TODO date(1) style format strings: --outfile out-%Y-%m-%d.log
        Settings.set("outfile", args.outfile)

	## Type of Service
    if args.tos:
        # TODO validate this. setsockopt() may be able to check this
        Settings.set("tos", args.tos)

	## Timeout
    if args.wait:
        try:
            Settings.set("wait", float(args.wait))
        except ValueError:
            fatal("[-] Value supplied for -w is not a number: %s" % args.wait)

	## Listening
    if args.localport:
        if valid_port(args.localport):
            Settings.set("localport", int(args.localport))
        else:
            fatal("[-] Invalid port: %s" % args.localport)
    if args.listen and not args.localport:
        fatal("[-] Listening requires a port to be specified with -p")

    ## Port or port range
    if args.ports:
        Settings.set("ports", build_port_list(args.ports))
        if Settings.get("ports") is None:
            fatal("[-] Invalid port range: %s" % args.ports)

	## Hostname/IP to connect to
    if args.host and not Settings.get("ports") and not Settings.get("listen"):
        fatal("[-] Must supply port or port range")
    if args.host:
        Settings.set("ip", args.host)
        if valid_ip_address(Settings.get("ip")) is False:
            if Settings.get("dns") is False:
                fatal("[-] Invalid IP address: %s" % Settings.get("ip"))
            if hostname_to_ip(Settings.get("ip")):
                Settings.set("resolved", args.host)
            else:
                fatal("[-] Invalid hostname: %s" % Settings.get("ip"))

    ## Randomize ports
    if args.randomize and Settings.get("ports"):
        randomized = Settings.get("ports")
        random.shuffle(randomized)
        Settings.set("ports", randomized)

    # TODO port and ports? nc default behavior is to attempt to bind() the
    #      port specified with -p, but "nc host port -p X" doesn't appear to
    #      use the -p value (but does still try to bind() it)
    #
    #      This can probably left as is for now to mimick netcat's behavior
    #      more accurately, but from rudimentary checks, -p seems to be
    #      ignored if 'ports' is specified.

    # if port list contains more than one port, -z must be set (or assumed)
    if len(Settings.get("ports")) > 1:
        Settings.set("zero", True)

    # Finally, listen must be set up or an IP set in order to continue
    if Settings.get("ports") is None and Settings.get("listen") is False:
        parser.print_help(sys.stderr)
        print(Settings.get("ports"))
        exit(os.EX_USAGE)


def main():
    """ main function -- entry point of the program.

    Args:
        None

    Returns:
        EX_OK on success
        EX_USAGE on failure
    """
    parse_cli()

    # listen
    if Settings.get("listen") is True:
        #
        print("listen %s:%s" % (Settings.get("ip"), Settings.get("localport")))
        return os.EX_OK

    # connect
    for port in Settings.get("ports"):
        sys.stdout.write("Connect to %s:%s " % (Settings.get("ip"), port))
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if Settings.get("wait"):
            sock.settimeout(Settings.get("wait"))
        try:
            sock.connect((Settings.get("ip"), port))
            print("Connected")
            connected = True
            while connected:
                select_list = [sys.stdin, sock]
                sel_r, sel_w, sel_e = select.select(select_list, [], [])

                for sock_r in sel_r:
                    if sock_r == sys.stdin:
                        client_input = sys.stdin.readline()
                        sock.send(client_input.encode())
                    elif sock_r == sock:
                        client_recv = sock.recv(1024).rstrip()
                        if client_recv:
                            print(client_recv.decode())
                        else:
                            sock.close()
                            connected = False
                            break
                for sock_w in sel_w:
                    print("write:")
                    print(sock_w)
                for sock_e in sel_e:
                    print("error:")
                    print(sock_e)

        except socket.timeout:
            print("Timed out")
        except ConnectionRefusedError:
            print("Connection refused")
        except BrokenPipeError:
            print("Broken Pipe")
        except EOFError:
            print("EOF")
        except KeyboardInterrupt:
            try:
                print()
                sys.stdout.write("rehash> ")
                cmd = input()
                print("you entered %s" % cmd)
            except KeyboardInterrupt:
                return os.EX_OK
    return os.EX_OK


if __name__ == "__main__":
    exit(main())

