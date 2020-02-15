import random

from scapy.all import ICMP, IP, ICMPv6EchoRequest, IPv6, Raw, sr1

from egress0r.message import InfoMessage, NegativeMessage, PositiveMessage
from egress0r.utils import is_ipv4_addr, is_ipv6_addr


class ICMPCheck:

    DEFAULT_TIMEOUT = 5
    START_MESSAGE = "Performing ICMP related checks..."

    def __init__(
        self,
        target_hosts,
        timeout=DEFAULT_TIMEOUT,
        exfil_payload=None,
        with_ipv4=True,
        with_ipv6=True,
    ):
        self.target_hosts = target_hosts
        self.exfil_payload = exfil_payload
        self.timeout = timeout
        self._with_ipv4 = with_ipv4
        self._with_ipv6 = with_ipv6

    def random_icmp_id(self):
        """Generate a random ICMP id value."""
        return random.randint(1, 32767)

    def _send_packet(self, pkt):
        return sr1(pkt, verbose=False, timeout=self.timeout)

    def ping_ipv4(self, target):
        """Request an ICMP Echo Reply from the target host via IPv4.
        Returns bool if the target responded.
        """
        random_id = self.random_icmp_id()
        packet = IP(dst=target) / ICMP(id=random_id)
        try:
            answer = self._send_packet(packet)
            return answer.payload.id == random_id
        except (TypeError, ValueError, AttributeError, KeyError):
            pass
        return False

    def ping_ipv6(self, target):
        """Request an ICMP echo reply from the target host via IPv6.
        Returns bool if the target responded.
        """
        random_id = self.random_icmp_id()
        packet = IPv6(dst=target) / ICMPv6EchoRequest(id=random_id)
        try:
            answer = self._send_packet(packet)
            return answer.payload.id == random_id
        except (TypeError, ValueError, AttributeError, KeyError):
            pass
        return False

    def exfil_ipv4(self, target, payload):
        """Exfiltrate the payoad via ICMP echo eequests over IPv4.
        Data is simply stored in the ICMP packet's payload without modification.
        """
        try:
            for chunk in payload.chunk_iter():
                random_id = self.random_icmp_id()
                packet = IP(dst=target) / ICMP(id=random_id) / Raw(load=chunk)
                answer = self._send_packet(packet)
                if chunk not in bytes(answer.payload.payload):
                    return False
        except (TypeError, ValueError, AttributeError, KeyError):
            return False
        return True

    def exfil_ipv6(self, target, payload):
        """Exfiltrate the payload ICMP echo requests over IPv6.
        Data is simply stored in the ICMP packet's payload without modification.
        """
        try:
            for chunk in payload.chunk_iter():
                random_id = self.random_icmp_id()
                packet = IPv6(dst=target) / ICMPv6EchoRequest(id=random_id, data=chunk)
                answer = self._send_packet(packet)
                if chunk not in bytes(answer.payload.data):
                    return False
        except (TypeError, ValueError, AttributeError, KeyError):
            return False
        return True

    def ping(self, target):
        """Ping the target.
        Returns: Bool indicating if the target sent an echo reply.
        """
        if is_ipv4_addr(target) is False and is_ipv6_addr(target) is False:
            raise ValueError(
                f"ICMPCheck.ping expected target to be an "
                f"IPv4 or IPv6 address, got {target!r}"
            )
        if is_ipv4_addr(target) and self._with_ipv4:
            return self.ping_ipv4(target)
        if is_ipv6_addr(target) and self._with_ipv6:
            return self.ping_ipv6(target)

    def _exfil(self, target, payload):
        """Exfiltrate the payload to the target.
        Returns: Bool indicating exfil success.
        """
        if is_ipv4_addr(target) is False and is_ipv6_addr(target) is False:
            raise ValueError(
                f"ICMPCheck.exfil expected target to be an "
                f"IPv4 or IPv6 address, got {target!r}"
            )
        if is_ipv4_addr(target) and self._with_ipv4:
            return self.exfil_ipv4(target, payload)
        if is_ipv6_addr(target) and self._with_ipv6:
            return self.exfil_ipv6(target, payload)

    def _to_message(self, target, status, payload=None):
        if payload:
            exfil_success = (
                f"Exfiltrated {payload.chunks_total_length} bytes to {target}"
            )
            exfil_fail = f"Failed to exfiltrate data to {target}"
        icmp_fail = f"No echo response from {target}"
        icmp_success = f"Received echo response from {target}"

        if status is True:
            msg = icmp_success
            if payload is not None:
                msg = exfil_success
            return PositiveMessage(msg)

        msg = icmp_fail
        if payload is not None:
            msg = exfil_fail
        return NegativeMessage(msg)

    def check(self):
        for target in self.target_hosts:
            if is_ipv4_addr(target) is False and is_ipv6_addr(target) is False:
                yield InfoMessage(f"Skipped target {target!r} because it's not an IP")
                continue
            if is_ipv4_addr(target) and not self._with_ipv4:
                continue
            if is_ipv6_addr(target) and not self._with_ipv6:
                continue
            status = self.ping(target)
            yield self._to_message(target, status)

            if self.exfil_payload:
                status = self._exfil(target, self.exfil_payload)
                yield self._to_message(target, status, self.exfil_payload)
