import ipaddress

import netifaces
from egress0r import config
from egress0r.utils import print_fail, print_info

HAS_IPV4_ADDR = None
HAS_IPV6_ADDR = None


def has_ipv4_addr():
    """Determine if the host has a private IPv4 address assigned."""
    for nic in netifaces.interfaces():
        for entry in netifaces.ifaddresses(nic).get(netifaces.AF_INET, []):
            if entry and entry.get("addr"):
                try:
                    addr = ipaddress.IPv4Address(entry["addr"])
                    if addr.is_loopback is False:
                        return True
                except ValueError:
                    continue
    return False


def has_ipv6_addr():
    """Determine if the host has a private IPv6 address assigned."""
    for nic in netifaces.interfaces():
        for entry in netifaces.ifaddresses(nic).get(netifaces.AF_INET6, []):
            try:
                addr = ipaddress.IPv6Address(entry["addr"])
                if addr.is_loopback is False and addr.is_link_local is False:
                    return True
            except (ValueError, KeyError, TypeError):
                continue
    return False


def override_check(cfg):
    global HAS_IPV4_ADDR
    global HAS_IPV6_ADDR
    try:
        override_ipv4 = cfg["sanity"]["override"]["ipv4"]
        override_ipv6 = cfg["sanity"]["override"]["ipv6"]
    except (KeyError, TypeError):
        return False
    if HAS_IPV4_ADDR is False and override_ipv4 == "enable":
        print_info(f"Forcefully enabling IPv4 tests")
        HAS_IPV4_ADDR = True
    elif HAS_IPV4_ADDR is True and override_ipv4 == "disable":
        print_info(f"Forcefully disabling IPv4 tests")
        HAS_IPV4_ADDR = False

    if HAS_IPV6_ADDR is False and override_ipv6 == "enable":
        print_info(f"Forcefully enabling IPv6 tests")
        HAS_IPV6_ADDR = True
    elif HAS_IPV6_ADDR is True and override_ipv6 == "disable":
        print_info(f"Forcefully disabling IPv6 tests")
        HAS_IPV6_ADDR = False

    return True


def ip_check(cfg):
    """Check if we have an IPv4 and/or IPv6 address assigned."""
    global HAS_IPV4_ADDR
    HAS_IPV4_ADDR = has_ipv4_addr()

    global HAS_IPV6_ADDR
    HAS_IPV6_ADDR = has_ipv6_addr()

    if not override_check(cfg):
        return False

    if not HAS_IPV6_ADDR and not HAS_IPV4_ADDR:
        print_fail("Neither IPv4 nor IPv6 is enabled, aborting...")
        return False

    if HAS_IPV6_ADDR:
        print_info("IPv6 tests enabled")
    else:
        print_info("IPv6 tests disabled")
    if HAS_IPV4_ADDR:
        print_info("IPv4 tests enabled")
    else:
        print_info("IPv4 tests disabled")
    return True


def check():
    """Perform sanity checks.
    Returns bool indicating a sane or insane environment. Depending on this
    value we either exit with an error or continue on our merry way.
    """
    print("\nPerforming sanity checks...")

    cfg = config.load()
    if not cfg:
        return False

    if not ip_check(cfg):
        return False

    print()
    return True
