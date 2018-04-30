import socket
import struct


def valid_ip_address(ip_address):
    ipv4 = valid_ipv4_address(ip_address)
    ipv6 = valid_ipv6_address(ip_address)
    return ipv4 | ipv6


def valid_ipv4_address(ip_address):
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        return False
    return True


def valid_ipv6_address(ip_address):
    try:
        socket.inet_pton(socket.AF_INET6, ip_address)
    except socket.error:
        return False
    return True


def valid_port(port):
    if int(port) > 0 and int(port) < 65536:
        return True
    return False


def ip_to_long(ip_address):
    tmp = socket.inet_aton(ip_address)
    return struct.unpack("!L", tmp)[0]


def long_to_ip(ip_address):
    tmp = struct.pack("!L", ip_address)
    return socket.inet_ntoa(tmp)


def network_from_cidr(ip_address, cidrmask):
    ip_addr = ip_to_long(ip_address)
    mask = (0xffffffff << 32 - int(cidrmask)) & 0xffffffff
    return long_to_ip(mask & ip_addr)


def hostname_to_ip(hostname):
    try:
        resolved = socket.getaddrinfo(hostname,
                                                  0,
                                                  0,
                                                  socket.SOCK_STREAM)
    except socket.gaierror:
        return None

    return resolved[0][4][0]

