""" network_common.py -- Various networking-related things.

    TODO: portlist_from_services() Windows support
"""

import socket
import struct
import string

def valid_ip_address(ip_address):
    """ valid_ip_address() -- Checks if input is a valid IP address.

    Args:
        ip_address (str) - address to validate.

    Returns:
        True if ip_address is valid.
        False if ip_address is not valid.
    """
    ipv4 = valid_ipv4_address(ip_address)
    ipv6 = valid_ipv6_address(ip_address)
    return ipv4 | ipv6


def valid_ipv4_address(ip_address):
    """ valid_ipv4_address() -- Checks if input is a valid IPv4 address.

    Args:
        ip_address (str) - address to validate.

    Returns:
        True if ip_address is valid.
        False if ip_address is not valid.
    """
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        return False
    return True


def valid_ipv6_address(ip_address):
    """ valid_ipv6_address() -- Checks if input is a valid IPv6 address.

    Args:
        ip_address (str) - address to validate.

    Returns:
        True if ip_address is valid.
        False if ip_address is not valid.
    """
    try:
        socket.inet_pton(socket.AF_INET6, ip_address)
    except socket.error:
        return False
    return True


def valid_port(port):
    """ valid_port() -- Checks if input is a valid port number.

    Args:
        port (int|str) - port number to validate.

    Returns:
        True if port is a valid port number.
        False if port is not a valid port number.
    """
    try:
        if int(port) > 0 and int(port) < 65536:
            return True
    except ValueError:
        return False
    return False


def build_portlist(portlist):
    """ build_portlist() -- Build list of ports using Nmap-style input.

    Args:
        portlist (str) - List of ports/port ranges.

    Returns:
        Unique list of ports on success.
        None on failure.

    Example:
        build_portlist("1-5,10,22-25") returns [1,2,3,4,5,10,22,23,24,25]
    """
    allowed = set(string.digits + "-" + ",")
    if (set(portlist) <= allowed) is False:
        return None
    ports = portlist.split(",")
    final = []
    for port in ports:
        if "-" in str(port):
            tmp = port.split("-")
            if len(tmp) != 2:
                return None
            if int(tmp[0]) > int(tmp[1]):
                return None
            final += range(int(tmp[0]), int(tmp[1]) + 1)
            continue
        final.append(int(port))
    if all(valid_port(port) for port in final) is True:
        return list(set(final))
    return None


def ip_to_long(ip_address):
    """ ip_to_long() -- Converts IP address to decimal.

    Args:
        ip_address (str) - IP address to convert.

    Returns:
        Decimal representation of ip_address.
    """
    tmp = socket.inet_aton(ip_address)
    return struct.unpack("!L", tmp)[0]


def long_to_ip(ip_address):
    """ long_to_ip() -- Converts decimal to IP address.

    Args:
        ip_address (int) - Number to convert to IP address.

    Returns:
        Quad notation IP address. Ex: "127.0.0.1"
    """
    tmp = struct.pack("!L", ip_address)
    return socket.inet_ntoa(tmp)


def network_from_cidr(ip_address, cidrmask):
    """ network_from_cidr() -- Returns network address from CIDR notation.

    Args:
        ip_address (str) - Network portion of CIDR mask. Ex: 127.0.0.0
        cidrmask (int) - CIDR netmask. Ex: 24

    Returns:
        String containing network address.

    Example:
        network_from_cidr("192.168.10.11", 24) returns "192.168.0.0"
    """
    ip_addr = ip_to_long(ip_address)
    mask = (0xffffffff << 32 - int(cidrmask)) & 0xffffffff
    return long_to_ip(mask & ip_addr)


def hostname_to_ip(hostname):
    """ hostname_to_ip() -- Resolves a hostname to an IP address.

    Args:
        hostname (str) - Hostname to resolve.

    Returns:
        First IP address of resolved hostname.

    Example:
        hostname_to_ip("www.google.com") returns "172.217.11.164"
    """
    try:
        resolved = socket.getaddrinfo(hostname, 0, 0, socket.SOCK_STREAM)
    except socket.gaierror:
        return None
    return resolved[0][4][0]


def protocol_from_socktype(socktype):
    """ protocol_from_socktype() -- Returns human-readable socket type.

    Args:
        socktype - socket type.

    Returns:
        "tcp" if socktype is TCP.
        "udp" if socktype is UDP.
        None if socktype is undetermined.
    """
    if socktype == socket.SOCK_STREAM:
        return "tcp"
    elif socktype == socket.SOCK_DGRAM:
        return "udp"
    else:
        return None


def portlist_from_services(protocol):
    """ portlist_from_services() -- Build a list of ports from "services" file.

    Args:
        protocol - tcp or udp.

    Returns:
        List of ports gleaned from /etc/services in the appropriate protocol
    """
    # TODO change location of services file if on Windows
    # TODO case sensitive?
    # TODO uniq this list?
    ports = []
    with open("/etc/services") as services:
        for line in services:
            if line.startswith("#") or line.isspace():
                continue
            tmp = line.split()
            if protocol in tmp[1]:
                ports.append(tmp[1].split("/")[0])
    return ports

