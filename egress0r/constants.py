import os

import colorama

main_dir = os.path.join(os.path.realpath(os.path.dirname(__file__)), "..")
egress0r_dir = os.path.join(main_dir, "egress0r")
data_dir = os.path.join(egress0r_dir, "data")
config_file = os.path.join(main_dir, "config.yml")
banner = (
    colorama.Fore.RED
    + r"""
                                         _______
  ____   ___________  ____   ______ _____\   _  \_______
_/ __ \ / ___\_  __ \/ __ \ /  ___//  ___/  /_\  \_  __ \
\  ___// /_/  |  | \\  ___/_\___ \ \___ \\  \_/   |  | \/
 \___  \___  /|__|   \___  /____  /____  >\_____  |__|
     \/_____/            \/     \/     \/       \/

"""
    + colorama.Fore.RESET
)
