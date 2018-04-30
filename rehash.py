#!/usr/bin/env python3

""" rehash.py -- Netcat-like hacking harness.
      by Daniel Roberson @dmfroberson                   April/2018
"""

import os
import socket
import string
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
        "interval" : 0,
        "ipv4" : False,
        "ipv6" : False,
        "keepalive" : False,
        "listen" : False,
        "logfile" : None,
        "port" : None,
        "randomize" : False,
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
        "interval",
        "ipv4",
        "ipv6",
        "keepalive",
        "listen",
        "logfile",
        "port",
        "randomize",
        "source",
        "telnet",
        "tos",
        "udp",
        "verbose",
        "wait",
        "zero",
    ]

    ip = ""
    resolved = ""
    ports = []

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
    print(msg)
    exit(os.EX_USAGE)


def parse_cli():
    """ parse_cli() -- Parse CLI arguments and check for sanity.

    Args:
        None

    Returns:
        ArgumentParser namespace of supplied CLI options
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

    # TODO fractional seconds: 0.1
    parser.add_argument(
        "-w",
        "--wait",
        default=0,
        help="Timeout (in seconds) for connects and final net reads")

    parser.add_argument(
        "-z",
        "--zeromode",
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
        "port",
        action="store",
        nargs="?",
        help="Port or range of ports. ex: 1-1024,8080")

    args = parser.parse_args()

    # Check sanity of supplied CLI arguments.

    # Make sure IPv4 and IPv6 aren't both specified. Default to IPv4.
    if args.ipv4 and args.ipv6:
        fatal("[-] Hey asshole. Pick either IPv4 or IPv6.")

    if not args.ipv4 and not args.ipv6:
        args.ipv4 = True

    Settings.set("dns", True if args.nodns is False else False)
    Settings.set("ipv4", args.ipv4)
    Settings.set("ipv6", args.ipv6)

    if args.host and args.listen:
        fatal("[-] wtf. -l option doesnt require a host argument")

    if args.host:
        # Verify hostname/ip address
        Settings.ip = args.host
        if valid_ip_address(Settings.ip) is False:
            if Settings.get("dns") is False:
                fatal("Invalid IP address: %s" % Settings.ip)
            Settings.ip = hostname_to_ip(Settings.ip)
            if Settings.ip is None:
                fatal("Invalid host: %s" % Settings.ip)
            else:
                Settings.resolved = args.host

    if args.port:
        # Parse the port list supplied via CLI and add each port to
        # the Settings.ports list. Make sure port numbers are valid.
        # No input via user should be unaccounted for and input should
        # be correct/logical.
        #
        # Ex: 1,2,3 => [1, 2, 3]
        #     1-3   => [1, 2, 3]
        #     1,2-3 => [1, 2, 3]
        #     1-2,3 => [1, 2, 3]
        #

        # TODO: This is uglier than sin. There has to be a better way
        # Verify supplied port string is correct and populate
        # Settings.ports[] with a list of ports to use.
        allowed = set(string.digits + "-" + ",")
        if (set(args.port) <= allowed) is False:
            fatal("Invalid port range: %s" % args.port)

        current = ""
        startport = ""
        for char in args.port:
            if char == ",":
                if current == "":
                    continue
                if not valid_port(int(current)):
                    fatal("Invalid port range: %s" % args.port)
                if startport and current:
                    if int(startport) > int(current):
                        fatal("Invalid port range: %s" % args.port)
                    # range() doesnt include last digit, so add one
                    for port in range(int(startport), int(current) + 1):
                        Settings.ports.append(int(port))
                    startport = ""
                    current = ""
                else:
                    Settings.ports.append(int(current))
                    current = ""
                    continue
            if char == "-":
                if startport:
                    fatal("Invalid port range: %s" % args.port)
                startport = current
                current = ""
                continue
            if char.isdigit():
                current += char
        # Deal with leftovers
        if startport and current:
            if not valid_port(int(current)) or \
                not valid_port(int(startport)):
                fatal("Invalid port range: %s" % args.port)
            if int(startport) > int(current):
                fatal("Invalid port range: %s" % args.port)
            for port in range(int(startport), int(current) + 1):
                Settings.ports.append(int(port))
        elif current:
            if valid_port(int(current)):
                Settings.ports.append(int(current))
            else:
                fatal("Invalid port range: %s" % args.port)
        print(Settings.ports)
    return args


def main():
    """ main function -- entry point of the program.

    Args:
        None

    Returns:
        Nothing
    """
    args = parse_cli()


if __name__ == "__main__":
    main()

