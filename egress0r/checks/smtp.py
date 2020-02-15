import smtplib
import socket
import traceback
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate

from egress0r.message import NegativeMessage, PositiveMessage


class SMTPCheck:
    """Exfiltrate test data via SMTP."""

    DEFAULT_TIMEOUT = 5
    ENCRYPTION_OPTIONS = (None, "tls", "ssl")
    START_MESSAGE = "Testing SMTP exfil..."

    def __init__(
        self,
        host,
        port,
        from_addr,
        to_addr,
        exfil_payload,
        encryption,
        username=None,
        password=None,
        subject=None,
        body=None,
        timeout=DEFAULT_TIMEOUT,
    ):
        """
        Arguments:
            host - SMTP host
            port - SMTP port
            from_addr - From which email address to send this message from.
            to_addr - recipient to send this email to.
            encryption - either None, tls or ssl.
            username - Optional, username to use for SMTP auth.
            password - Optional, password to use for SMTP auth.
            subject - Optional, the subject for the email.
            body - Optional the body of the email.
            timeout - How long to wait for in seconds before aborting.
        """
        self.host = host
        self.port = port
        self.from_addr = from_addr
        self.to_addr = to_addr
        self.exfil_payload = exfil_payload
        self.encryption = encryption
        if encryption not in self.ENCRYPTION_OPTIONS:
            raise ValueError(
                "SMTPCheck.encryption argument must "
                f"be one of {self.ENCRYPTION_OPTIONS}"
            )
        self.username = username
        self.password = password
        self.subject = subject
        self.body = body
        self.timeout = timeout

    def build_msg(
        self, from_addr, to_addr, body=None, subject=None, exfil_payload=None
    ):
        msg = MIMEMultipart()
        msg["From"] = from_addr
        msg["To"] = to_addr
        msg["Date"] = formatdate(localtime=True)
        if subject is not None:
            msg["Subject"] = subject

        # Take care of the body, here we either submit the exfil data as an
        # attachment or add the exfil data to the email body itself.
        body_raw = body or ""
        body_raw = body_raw
        if exfil_payload:
            if exfil_payload.exfil_mode == "attachment":
                multipart = MIMEApplication(
                    exfil_payload.read(), Name=exfil_payload.filename
                )
                multipart[
                    "Content-Disposition"
                ] = f'attachment; filename="{exfil_payload.filename}"'
                msg.attach(multipart)
            else:
                body_raw += "\r\r" + exfil_payload.read().decode(
                    "utf8", errors="replace"
                )
        msg.attach(MIMEText(body_raw))
        return msg

    def _exfil(self, payload):
        smtp_client = smtplib.SMTP
        if self.encryption == "ssl":
            smtp_client = smtplib.SMTP_SSL

        try:
            with smtp_client(self.host, self.port, timeout=self.timeout) as smtp:
                if self.encryption == "tls":
                    smtp.starttls()
                if self.username is not None and self.password is not None:
                    smtp.login(self.username, self.password)

                msg = self.build_msg(
                    self.from_addr, self.to_addr, self.body, self.subject, payload
                )
                smtp.send_message(msg, self.from_addr, self.to_addr)
                return True
        except (smtplib.SMTPException, socket.gaierror, socket.timeout, OSError):
            # traceback.print_exc()
            pass
        return False

    def check(self):
        success = self._exfil(self.exfil_payload)
        if success is True:
            yield PositiveMessage(f"Exfiltrated {self.exfil_payload.data_length} bytes")
            return
        yield NegativeMessage("Failed to exfiltrate data")
        return
