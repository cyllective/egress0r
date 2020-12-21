import colorama

from egress0r import config, constants, factory, sanity


def print_outcome(success_count, fail_count):
    checkmark = colorama.Fore.LIGHTGREEN_EX + "✓" + colorama.Fore.RESET
    redx = colorama.Fore.LIGHTRED_EX + "x" + colorama.Fore.RESET
    print(
        f"Summary:  [{checkmark}] Successful tests: {success_count}"
        f"    [{redx}] Failed tests: {fail_count}"
    )


def main():
    print(constants.banner)

    is_sane = sanity.check()
    if not is_sane:
        exit(1)

    cfg = config.load()

    services = {
        "dns": factory.build_dns,
        "icmp": factory.build_icmp,
        "smtp": factory.build_smtp,
        "http": factory.build_http,
        "ftp": factory.build_ftp,
        "port": factory.build_port,
    }

    success = 0
    fail = 0
    for service_name, service_factory in services.items():
        if cfg["check"][service_name] is True:
            service = service_factory(cfg[service_name])
            print(service.START_MESSAGE)
            for message in service.check():
                if message:
                    success += 1
                    message.print()
                else:
                    fail += 1
                    message.print()
            print()

    print_outcome(success, fail)


if __name__ == "__main__":
    colorama.init()
    try:
        main()
    except KeyboardInterrupt:
        pass
    finally:
        colorama.deinit()
