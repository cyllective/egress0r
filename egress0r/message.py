import datetime
import enum

from colorama import Fore


class MessageType(enum.IntEnum):
    FAIL = 3
    SUCCESS = 6
    INFO = 98
    UNKNOWN = 99


class Message:
    """Holds information about a performed test step."""

    INDICATOR_MAP = {
        MessageType.FAIL.name: Fore.LIGHTRED_EX + "x" + Fore.RESET,
        MessageType.SUCCESS.name: Fore.LIGHTGREEN_EX + "✓" + Fore.RESET,
        MessageType.INFO.name: Fore.LIGHTBLUE_EX + "*" + Fore.RESET,
        MessageType.UNKNOWN.name: Fore.LIGHTYELLOW_EX + "?" + Fore.RESET,
    }

    def __init__(self, message, type_=None, when=None):
        self.message = message
        self.type_ = type_
        if type_ is None:
            self.type_ = MessageType.INFO
        self.when = when or datetime.datetime.utcnow()

    def print(self, indent=4):
        indicator = self.INDICATOR_MAP[self.type_.name]
        print(f'{" "*indent}[{self.when}]    [{indicator}] {self.message}')

    def __str__(self):
        return (
            f"{self.__class__.__qualname__}(message={self.message!r}, "
            f"type_={self.type_}, "
            f"when={self.when})"
        )


class PositiveMessage(Message):
    def __init__(self, message, when=None):
        super().__init__(message, type_=MessageType.SUCCESS, when=when)


class NegativeMessage(Message):
    def __init__(self, message, when=None):
        super().__init__(message, type_=MessageType.FAIL, when=when)

    def __bool__(self):
        return False


class UnknownMessage(Message):
    def __init__(self, message, when=None):
        super().__init__(message, type_=MessageType.UNKNOWN, when=when)


class InfoMessage(Message):
    def __init_(self, message, when=None):
        super().__init__(message, type_=MessageType.INFO, when=when)
