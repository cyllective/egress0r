import io
import os
import socket
import uuid
from multiprocessing import Pool

import pycurl
from scapy.all import UDP, IPv6, IP, Raw, sr1

from egress0r.constants import data_dir
from egress0r.utils import print_by_status, ip_to_url
from egress0r.message import PositiveMessage, NegativeMessage


class PortCheck:
    """Check for unfiltered egress ports."""

    PORT_MIN = 1
    PORT_MAX = 65535
    DEFAULT_UDP_TIMEOUT = 6
    DEFAULT_TCP_TIMEOUT = 6
    DEFAULT_WITH_UDP = True
    DEFAULT_WITH_TCP = True
    VALID_MODES = ('top10', 'top100', 'all')
    DEFAULT_MODE = 'top10'
    START_MESSAGE = 'Performing egress port checks...'

    def __init__(self, ipv4_addr, ipv6_addr, mode=DEFAULT_MODE,
                 udp_timeout=DEFAULT_UDP_TIMEOUT, tcp_timeout=DEFAULT_TCP_TIMEOUT,
                 with_udp=DEFAULT_WITH_UDP, with_tcp=DEFAULT_WITH_TCP,
                 with_ipv4=True, with_ipv6=True):
        self.ipv4_addr = ipv4_addr
        self.ipv6_addr = ipv6_addr
        self._mode = mode
        self.udp_timeout = udp_timeout
        self.tcp_timeout = tcp_timeout
        self.with_udp = with_udp
        self.with_tcp = with_tcp
        self._with_ipv4 = with_ipv4
        self._with_ipv6 = with_ipv6
        self._identifier = str(uuid.uuid4())

    @property
    def mode(self):
        return self._mode

    @mode.setter
    def mode(self, m):
        if m not in self.VALID_MODES:
            raise ValueError(f'PortCheck expects argument "mode" to be one of {self.VALID_MODES} '
                             f'but got {m!r}.')
        self._mode = m

    def _setup_curl(self, url, timeout=None):
        if timeout is None:
            timeout = self.tcp_timeout
        buf = io.BytesIO()
        curl = pycurl.Curl()
        curl.setopt(pycurl.URL, url)
        curl.setopt(pycurl.WRITEDATA, buf)
        curl.setopt(pycurl.USERAGENT, 'curl/7.59.0')
        curl.setopt(pycurl.TIMEOUT, timeout)
        return curl, buf

    def connect_ipv4_tcp(self, port):
        url = ip_to_url(self.ipv4_addr, port=port)
        try:
            curl, buf = self._setup_curl(url)
            curl.perform()
        except(pycurl.error, socket.timeout):
            return port, False

        keyword = f'Port: {port} reached.'
        response = buf.getvalue().decode('utf8', errors='replace')
        buf.close()
        curl.close()
        return port, keyword in response

    def connect_ipv4_udp(self, port):
        pkt = IP(dst=self.ipv4_addr)/UDP(dport=port)/Raw(load=self._identifier)
        response = ''
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.udp_timeout)
                sock.sendto(bytes(pkt), (self.ipv4_addr, port))
                response = sock.recvfrom(1024)
        except(socket.timeout, TypeError, OSError):
            pass
        return port, self._identifier in str(response)

    def connect_ipv6_tcp(self, port):
        url = ip_to_url(self.ipv6_addr, port=port)
        try:
            curl, buf = self._setup_curl(url)
            curl.perform()
        except(pycurl.error, socket.timeout):
            return port, False

        keyword = f'Port: {port} reached.'
        response = buf.getvalue().decode('utf8', errors='replace')
        buf.close()
        curl.close()
        return port, keyword in response

    def connect_ipv6_udp(self, port):
        pkt = IPv6(dst=self.ipv6_addr)/UDP(dport=port)/Raw(load=self._identifier)
        response = ''
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.udp_timeout)
                sock.sendto(bytes(pkt), (self.ipv6_addr, port))
                response = sock.recvfrom(1024)
        except(socket.timeout, TypeError, OSError):
            pass
        return port, self._identifier in str(response)

    def all_ports(self):
        return tuple(range(self.PORT_MIN, self.PORT_MAX+1))

    def top_100_ports(self):
        ports = []
        with open(os.path.join(data_dir, 'top-100-ports.txt')) as fin:
            for line in fin.readlines():
                try:
                    port = int(line.strip())
                    if self.PORT_MIN-1 < port < self.PORT_MAX+1:
                        ports.append(port)
                except(ValueError, TypeError):
                    pass

        return tuple(ports)

    def top_10_ports(self):
        ports = []
        with open(os.path.join(data_dir, 'top-10-ports.txt')) as fin:
            for line in fin.readlines():
                try:
                    port = int(line.strip())
                    if self.PORT_MIN-1 < port < self.PORT_MAX+1:
                        ports.append(port)
                except(ValueError, TypeError):
                    pass

        return tuple(ports)

    def check_tcp_ports(self, port_iter, ip_version=4):
        pool = Pool()
        check_func = self.connect_ipv4_tcp
        if ip_version == 6:
            check_func = self.connect_ipv6_tcp
        for port, status in pool.imap(check_func, iterable=port_iter):
            yield port, status

    def check_udp_ports(self, port_iter, ip_version=4):
        pool = Pool()
        check_func = self.connect_ipv4_udp
        if ip_version == 6:
            check_func = self.connect_ipv6_udp
        for port, status in pool.imap(check_func, iterable=port_iter):
            yield port, status

    def _message_producer(self, port, protocol, status, host):
        success_msg = f'Connected via {port}/{protocol} to {host}'
        fail_msg = f'Failed to connect via {port}/{protocol} to {host}'
        if status:
            return PositiveMessage(success_msg)
        return NegativeMessage(fail_msg)

    def check(self):
        """Check for port filtering."""
        if self.mode == 'all':
            ports = self.all_ports()
        elif self.mode == 'top100':
            ports = self.top_100_ports()
        elif self.mode == 'top10':
            ports = self.top_10_ports()
        else:
            raise ValueError(f'PortCheck.mode must be in {self.VALID_MODES}, got {self.mode!r}')

        if self.with_tcp:
            if self._with_ipv4 and self.ipv4_addr:
                for port, status in self.check_tcp_ports(ports, ip_version=4):
                    yield self._message_producer(port, 'tcp', status, self.ipv4_addr)
            if self._with_ipv6 and self.ipv6_addr:
                for port, status in self.check_tcp_ports(ports, ip_version=6):
                    yield self._message_producer(port, 'tcp', status, self.ipv6_addr)

        if self.with_udp:
            if self._with_ipv4 and self.ipv4_addr:
                for port, status in self.check_udp_ports(ports, ip_version=4):
                    yield self._message_producer(port, 'udp', status, self.ipv4_addr)
            if self._with_ipv6 and self.ipv6_addr:
                for port, status in self.check_udp_ports(ports, ip_version=6):
                    yield self._message_producer(port, 'udp', status, self.ipv6_addr)
