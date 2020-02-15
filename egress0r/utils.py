import datetime
import ipaddress
import os
import random
import string

import colorama

from egress0r import constants


def _fmt_msg(status, message, indent=4, timestamp=None):
    timestamp_ = timestamp or datetime.datetime.utcnow().strftime(
        "%Y-%m-%d %H:%M:%S.%f"
    )
    return f'{" "*indent}[{timestamp_}]    [{status}] {message}'


def print_success(message, indent=4):
    status = colorama.Fore.LIGHTGREEN_EX + "✓" + colorama.Fore.RESET
    print(_fmt_msg(status, message, indent))


def print_fail(message, indent=4):
    status = colorama.Fore.LIGHTRED_EX + "x" + colorama.Fore.RESET
    print(_fmt_msg(status, message, indent))


def print_unknown(message, indent=4):
    status = colorama.Fore.LIGHTMAGENTA_EX + "?" + colorama.Fore.RESET
    print(_fmt_msg(status, message, indent))


def print_info(message, indent=4):
    status = colorama.Fore.LIGHTCYAN_EX + "*" + colorama.Fore.RESET
    print(_fmt_msg(status, message, indent))


def print_by_status(message, status):
    if status is True:
        print_success(message)
    else:
        print_fail(message)


def random_filename(length=15, extension=None):
    name = "".join(random.choices(string.ascii_letters + string.digits, k=length))
    if extension:
        if extension.startswith("."):
            extension = extension[1:]
        name += "." + extension
    return name


def load_exfil_data(filename, mode=None):
    if not mode:
        mode = "r"
    with open(os.path.join(constants.data_dir, filename), mode) as fin:
        return fin.read()


def is_ipv4_addr(addr):
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

    Examples:
        ip_to_url('127.0.0.1', scheme=None, port=None) -> 'http://127.0.0.1/'
        ip_to_url('127.0.0.1', scheme=None, port=8080) -> 'http://127.0.0.1:8080/'
        ip_to_url('::1', scheme=None, port=8800) -> 'http://[::1]:8800/'
        ip_to_url('::1', scheme=https, port=8443) -> 'https://[::1]:8443/'
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

    if port is None or port == 80:
        url += "/"
    else:
        url += f":{port}/"
    return url
