import datetime
import ipaddress
import random
import string

import colorama


def _fmt_msg(status, message, timestamp=None):
    timestamp_ = timestamp or datetime.datetime.utcnow().strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )
    return f'[{timestamp_}]    [{status}] {message}'


def print_fail(message):
    status = colorama.Fore.LIGHTRED_EX + "x" + colorama.Fore.RESET
    print(_fmt_msg(status, message))


def print_info(message):
    status = colorama.Fore.LIGHTCYAN_EX + "*" + colorama.Fore.RESET
    print(_fmt_msg(status, message))


def random_filename(length=15, extension=None):
    name = "".join(random.choices(string.ascii_letters + string.digits, k=length))
    if extension:
        if extension.startswith("."):
            extension = extension[1:]
        name += "." + extension
    return name


def is_ipv4_addr(addr):
    """
    Determine if the passed ``addr`` is a valid IPv4 address.

    :param addr: the string to check
    :return: bool
    """
    """Determine if the passed address string is a valid IPv4 addresss.
    Returns bool.
    """
    try:
        return bool(ipaddress.IPv4Address(addr))
    except ValueError:
        pass
    return False


def is_ipv6_addr(addr):
    """Determine if the passed address string is a valid IPv6 addresss.
    Returns bool.
    """
    try:
        return bool(ipaddress.IPv6Address(addr))
    except ValueError:
        pass
    return False


def ip_to_url(addr, scheme=None, port=None):
    """Transform IPv4 and IPv6 addresses to URLs.

    >>> ip_to_url("127.0.0.1", scheme=None, port=None)
    'http://127.0.0.1/'

    >>> ip_to_url("127.0.0.1", scheme="http", port=80)
    'http://127.0.0.1/'

    >>> ip_to_url("127.0.0.1", scheme=None, port=8080)
    'http://127.0.0.1:8080/'

    >>> ip_to_url("127.0.0.1", scheme="https", port=None)
    'https://127.0.0.1/'

    >>> ip_to_url("127.0.0.1", scheme="https", port=443)
    'https://127.0.0.1/'

    >>> ip_to_url("::1", scheme=None, port=8800)
    'http://[::1]:8800/'

    >>> ip_to_url("::1", scheme="https", port=8443)
    'https://[::1]:8443/'
    """
    if not scheme:
        scheme = "http"
    if is_ipv4_addr(addr):
        url = f"{scheme}://{addr}"
    elif is_ipv6_addr(addr):
        url = f"{scheme}://[{addr}]"
    else:
        raise ValueError(
            "ip_to_url expected argument 'addr' to be an IPv4 or IPv6 address."
        )

    if port in (None, 80):
        url += "/"
    elif port in (None, 443) and scheme == "https":
        url += "/"
    else:
        url += f":{port}/"
    return url
