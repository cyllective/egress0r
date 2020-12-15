import ftplib

from egress0r.message import NegativeMessage, PositiveMessage
from egress0r.utils import random_filename


class FTPCheck:

    DEFAULT_TIMEOUT = 5
    START_MESSAGE = "Testing FTP exfil..."

    def __init__(
        self,
        host,
        exfil_payload,
        upload_dir=None,
        username=None,
        password=None,
        timeout=None,
    ):
        self.host = host
        self.username = username or "anonymous"
        self.password = password or "anonymous@"
        self.upload_dir = upload_dir
        self.exfil_payload = exfil_payload
        self.timeout = timeout

    def upload(self, payload, upload_dir=None):
        """Upload the payload to the configured remote host."""
        filename = random_filename(length=120, extension=".bin")
        try:
            with ftplib.FTP(
                self.host, self.username, self.password, timeout=self.timeout
            ) as ftp:
                ftp.getwelcome()

                if upload_dir:
                    ftp.cwd(upload_dir)

                result = ftp.storlines(f"STOR {filename}", payload.filehandle)
                if "226 Transfer complete" in result:
                    return True
        except ftplib.all_errors:
            pass

        return False

    def check(self):
        status = self.upload(self.exfil_payload, self.upload_dir)
        if status is True:
            yield PositiveMessage(
                f"Exfiltrated {self.exfil_payload.data_length} bytes to {self.host}"
            )
        else:
            yield NegativeMessage(f"Failed to exfiltrate data to {self.host}")
