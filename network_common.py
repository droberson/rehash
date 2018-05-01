import socket
import struct
import string

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
    try:
        if int(port) > 0 and int(port) < 65536:
            return True
    except ValueError:
        return False
    return False


# Nmap style port ranges: 1-5,10,60-90,100
def build_port_list(portlist):
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
        return set(final)
    return None


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

