import traceback

from egress0r import sanity
from egress0r.checks import (
    FTPCheck,
    HTTPVerbsCheck,
    ICMPCheck,
    DNSCheck,
    PortCheck,
    SMTPCheck,
)
from egress0r.checks.dns_ import Query
from egress0r.payload import DNSExfilPayload, ExfilPayload, SMTPExfilPayload


def build_smtp_exfil_payload(config):
    """Build an SMTPExfilPayload object with the given config."""
    return SMTPExfilPayload(
        filename=config["filename"],
        read_mode=config.get("read_mode", SMTPExfilPayload.DEFAULT_READ_MODE),
        exfil_mode=config.get("exfil_mode", SMTPExfilPayload.DEFAULT_EXFIL_MODE),
    )


def build_smtp(config, overrides=None):
    """Build an SMTPCheck object with the given config."""
    if overrides:
        config.update(overrides)

    exfil_payload = build_smtp_exfil_payload(config["exfil"])
    return SMTPCheck(
        host=config["host"],
        port=int(config["port"]),
        from_addr=config["from_addr"],
        to_addr=config["to_addr"],
        encryption=config["encryption"],
        username=config.get("username", None),
        password=config.get("password", None),
        subject=config.get("subject", None),
        body=config.get("message", None),
        exfil_payload=exfil_payload,
        timeout=int(config.get("timeout", SMTPCheck.DEFAULT_TIMEOUT)),
    )


def build_http(config, overrides=None):
    """Build an HTTPVerbsCheck object with the given config."""
    if overrides:
        config.update(overrides)
    proxies = None
    if all(config.get("proxies", {}).values()):
        proxies = config["proxies"]
    exfil_payload = ExfilPayload(config["exfil"]["filename"], read_mode="r")
    return HTTPVerbsCheck(
        verbs=config["verbs"],
        urls=config["urls"],
        proxies=proxies,
        exfil_payload=exfil_payload,
    )


def build_dns_exfil_payload(config):
    """Build a DNSExfilPayload object with the given config."""
    return DNSExfilPayload(
        filename=config["filename"],
        domain=config["domain"],
        record_type=config["record_type"],
        nameserver=config["nameserver"],
        chunk_size=int(config.get("chunk_size", DNSExfilPayload.DEFAULT_CHUNK_SIZE)),
        max_chunks=int(config.get("max_chunks", DNSExfilPayload.DEFAULT_MAX_CHUNKS)),
    )


def build_dns_queries(config):
    """Build a tuple of egress0r.nameserver.Query objects.

    Attributes:
        config - list of dicts with queries:

            [
                {'record': 'domain.xyz', 'record_type': 'A'},
                {'record': 'domain.xyz', 'record_type': 'AAAA'},
                {'record': 'one.one.one.one', 'record_type': 'A', expected_answers: [
                    '1.1.1.1',
                    '1.0.0.1'
                ]}
                ...
            ]
    """
    queries = []
    for query in config:
        if isinstance(query, Query):
            queries.append(query)
        else:
            queries.append(Query(**query))
    return tuple(queries)


def build_dns(config, overrides=None):
    """Build a DNSCheck object with the given config."""
    if overrides:
        config.update(overrides)

    queries = build_dns_queries(config["queries"])
    payload = None
    try:
        if all(
            (
                config["exfil"].get("domain"),
                config["exfil"].get("nameserver"),
                config["exfil"].get("record_type"),
                config["exfil"].get("filename"),
            )
        ):
            payload = build_dns_exfil_payload(config["exfil"])
    except (KeyError, AttributeError, TypeError):
        pass
    return DNSCheck(
        dns_servers=config["servers"],
        queries=queries,
        timeout=int(config.get("timeout", DNSCheck.DEFAULT_TIMEOUT)),
        exfil_payload=payload,
        with_ipv4=sanity.HAS_IPV4_ADDR,
        with_ipv6=sanity.HAS_IPV6_ADDR,
    )


def build_port(config, overrides=None):
    """Build a PortCheck object with the given config."""
    if overrides:
        config.update(overrides)
    return PortCheck(
        ipv4_addr=config["ipv4_addr"],
        ipv6_addr=config["ipv6_addr"],
        mode=config.get("mode", PortCheck.DEFAULT_MODE),
        udp_timeout=int(config.get("udp_timeout", PortCheck.DEFAULT_UDP_TIMEOUT)),
        tcp_timeout=int(config.get("tcp_timeout", PortCheck.DEFAULT_TCP_TIMEOUT)),
        with_tcp=config.get("with_tcp", PortCheck.DEFAULT_WITH_TCP),
        with_udp=config.get("with_tcp", PortCheck.DEFAULT_WITH_UDP),
        with_ipv4=sanity.HAS_IPV4_ADDR,
        with_ipv6=sanity.HAS_IPV6_ADDR,
    )


def build_icmp_exfil_payload(config):
    """Build an ExfilPayload object for ICMPCheck with the given config."""
    return ExfilPayload(
        filename=config["filename"],
        read_mode="rb",
        chunk_size=config["chunk_size"],
        max_chunks=config["max_chunks"],
    )


def build_icmp(config, overrides=None):
    """Build an ICMPCheck object with the given config."""
    if overrides:
        config.update(overrides)

    exfil_payload = None
    try:
        exfil_payload = build_icmp_exfil_payload(config["exfil"])
    except (KeyError, AttributeError):
        traceback.print_exc()
    return ICMPCheck(
        target_hosts=config["target_hosts"],
        timeout=int(config.get("timeout", ICMPCheck.DEFAULT_TIMEOUT)),
        exfil_payload=exfil_payload,
        with_ipv4=sanity.HAS_IPV4_ADDR,
        with_ipv6=sanity.HAS_IPV6_ADDR,
    )


def build_ftp(config, overrides=None):
    """Build an FTPCheck object with the given config."""
    if overrides:
        config.update(overrides)
    exfil_payload = ExfilPayload(filename=config["exfil"]["filename"])
    return FTPCheck(
        host=config["host"],
        exfil_payload=exfil_payload,
        upload_dir=config["upload_dir"],
        username=config.get("username", None),
        password=config.get("password", None),
        timeout=config.get("timeout", None),
    )
