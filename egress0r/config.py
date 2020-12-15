import cerberus
import yaml

from egress0r.constants import config_file
from egress0r.utils import print_fail

cfg = None


def validate(config):
    schema = {
        "sanity": {
            "type": "dict",
            "required": True,
            "schema": {
                "override": {
                    "type": "dict",
                    "required": True,
                    "schema": {
                        "ipv4": {
                            "allowed": [None, "enable", "disable"],
                            "nullable": True,
                        },
                        "ipv6": {
                            "allowed": [None, "enable", "disable"],
                            "nullable": True,
                        },
                    },
                }
            },
        },
        "auth": {
            "type": "dict",
            "required": True,
            "schema": {
                "token": {"type": "string", "required": True},
                "ipv4_url": {"type": "string", "required": True, "empty": False},
                "ipv6_url": {"type": "string", "required": True, "empty": False},
            },
        },
        "check": {
            "type": "dict",
            "required": True,
            "schema": {
                "port": {"type": "boolean", "required": True},
                "icmp": {"type": "boolean", "required": True},
                "http": {"type": "boolean", "required": True},
                "smtp": {"type": "boolean", "required": True},
                "dns": {"type": "boolean", "required": True},
                "ftp": {"type": "boolean", "required": True},
            },
        },
        "smtp": {
            "type": "dict",
            "required": True,
            "schema": {
                "timeout": {"type": "integer", "required": True, "min": 1},
                "host": {"type": "string", "required": True, "empty": False},
                "port": {"type": "integer", "required": True},
                "encryption": {"allowed": [None, "tls", "ssl"], "nullable": True},
                "from_addr": {
                    "type": "string",
                    "required": True,
                    "empty": False,
                    "regex": r".+?@.+\..+",
                },
                "to_addr": {"type": "string", "required": True, "regex": r".+?@.+\..+"},
                "username": {
                    "required": True,
                    "type": "string",
                    "nullable": True,
                    "empty": False,
                },
                "password": {
                    "required": True,
                    "type": "string",
                    "nullable": True,
                    "empty": False,
                },
                "exfil": {
                    "type": "dict",
                    "required": True,
                    "empty": False,
                    "schema": {
                        "filename": {
                            "type": "string",
                            "empty": False,
                            "required": True,
                        },
                        "payload_mode": {
                            "type": "string",
                            "empty": False,
                            "required": True,
                            "allowed": ["attachment", "inline"],
                        },
                    },
                },
                "message": {
                    "type": "string",
                    "empty": True,
                    "required": False,
                    "nullable": True,
                },
                "subject": {"type": "string", "required": True, "empty": False},
            },
        },
        "port": {
            "type": "dict",
            "required": True,
            "schema": {
                "mode": {"type": "string", "allowed": ["top10", "top100", "all"]},
                "ipv4_addr": {
                    "type": "string",
                    "required": True,
                    "empty": False,
                    "regex": r"^(\d{1,3}\.){3}\d{1,3}$",
                },
                "ipv6_addr": {
                    "type": "string",
                    "required": True,
                    "empty": False,
                    "regex": r"^[0-9a-fA-F:]+$",
                },
                "with_tcp": {"type": "boolean", "required": True},
                "tcp_timeout": {"type": "integer", "required": True, "min": 1},
                "with_udp": {"type": "boolean", "required": True},
                "udp_timeout": {"type": "integer", "required": True, "min": 1},
            },
        },
        "http": {
            "type": "dict",
            "required": True,
            "schema": {
                "timeout": {"type": "integer", "required": True, "min": 1},
                "exfil": {
                    "type": "dict",
                    "required": True,
                    "empty": False,
                    "schema": {
                        "filename": {"type": "string", "required": True, "empty": False}
                    },
                },
                "verbs": {
                    "type": "list",
                    "required": True,
                    "allowed": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                },
                "urls": {
                    "type": "list",
                    "required": True,
                    "schema": {"type": "string", "regex": r"^http(s)?://.*$"},
                },
                "proxies": {
                    "type": "dict",
                    "required": True,
                    "schema": {
                        "http": {
                            "type": "string",
                            "nullable": True,
                            "regex": r"^(http(s)?|socks5)://.+",
                        },
                        "https": {
                            "type": "string",
                            "nullable": True,
                            "regex": r"^(http(s)?|socks5)://.+",
                        },
                    },
                },
            },
        },
        "icmp": {
            "type": "dict",
            "required": True,
            "schema": {
                "timeout": {"type": "integer", "required": True, "min": 1},
                "exfil": {
                    "type": "dict",
                    "required": True,
                    "empty": False,
                    "schema": {
                        "filename": {
                            "type": "string",
                            "empty": False,
                            "required": True,
                        },
                        "max_chunks": {"type": "integer", "min": 1, "required": True},
                        "chunk_size": {"type": "integer", "min": 1, "required": True},
                    },
                },
                "target_hosts": {
                    "type": "list",
                    "required": True,
                    "schema": {
                        "type": "string",
                        "required": True,
                        "empty": False,
                        "regex": r"^((\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)$",
                    },
                },
            },
        },
        "dns": {
            "type": "dict",
            "required": True,
            "schema": {
                "timeout": {"type": "integer", "required": True, "min": 1},
                "servers": {
                    "type": "list",
                    "required": True,
                    "schema": {
                        "type": "string",
                        "required": True,
                        "empty": False,
                        "regex": r"^((\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)$",
                    },
                },
                "exfil": {
                    "type": "dict",
                    "required": True,
                    "empty": False,
                    "schema": {
                        "filename": {
                            "type": "string",
                            "empty": False,
                            "required": True,
                        },
                        "nameserver": {
                            "type": "string",
                            "required": True,
                            "empty": False,
                            "regex": r"^((\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)$",
                        },
                        "domain": {"type": "string", "required": True, "empty": False},
                        "record_type": {
                            "type": "string",
                            "required": True,
                            "empty": False,
                            "allowed": ["A", "AAAA", "MX", "TXT"],
                        },
                        "max_chunks": {"type": "integer", "min": 1, "required": True},
                        "chunk_size": {"type": "integer", "min": 1, "required": True},
                    },
                },
                "queries": {
                    "type": "list",
                    "required": True,
                    "schema": {
                        "type": "dict",
                        "required": True,
                        "empty": False,
                        "schema": {
                            "record": {
                                "type": "string",
                                "required": True,
                                "empty": False,
                            },
                            "record_type": {
                                "type": "string",
                                "required": True,
                                "empty": False,
                                "allowed": ["A", "AAAA", "MX", "TXT"],
                            },
                            "expected_answers": {"type": "list", "required": False},
                        },
                    },
                },
            },
        },
        "ftp": {
            "type": "dict",
            "required": True,
            "empty": False,
            "schema": {
                "timeout": {"type": "integer", "required": True, "min": 1},
                "host": {"type": "string", "required": True, "empty": False},
                "username": {"type": "string", "required": True, "empty": False},
                "password": {"type": "string", "required": True, "empty": False},
                "upload_dir": {"type": "string", "required": True, "nullable": True},
                "exfil": {
                    "type": "dict",
                    "required": True,
                    "empty": False,
                    "schema": {
                        "filename": {"type": "string", "empty": False, "required": True}
                    },
                },
            },
        },
    }
    try:
        validator = cerberus.Validator(schema)
        is_valid = validator.validate(config)
        return is_valid, validator.errors
    except cerberus.validator.DocumentError as e:
        return False, f"Config file error: {e}"


def load(print_errors=True):
    """Load the config from ./config.yml
    Returns the config, parsed via yaml to a dict, on success and None on failure.
    If the argument print_errors is set to True, the config error message is printed.
    """
    global cfg
    if cfg is None:
        try:
            with open(config_file) as cf:
                cfg = yaml.safe_load(cf)
        except (OSError, FileNotFoundError):
            if print_errors:
                print_fail(
                    "Config file not found or unable to read, "
                    "refer to the documentation on how to configure egress0r."
                )
            return None

        is_valid, errors = validate(cfg)
        if not is_valid:
            if print_errors:
                print_fail("Config file contains invalid content.")
                print(errors)
            return None

    return cfg
