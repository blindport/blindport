"""Bounded synchronous SMTP delivery using the Python standard library."""

from __future__ import annotations

import smtplib
import ssl
from contextlib import suppress
from email.message import EmailMessage
from email.policy import SMTP
from enum import StrEnum


class SmtpSecurity(StrEnum):
    STARTTLS = "starttls"
    TLS = "tls"


class SmtpDeliveryError(RuntimeError):
    """Sanitized SMTP failure safe to persist."""

    def __init__(self, code: str, *, retryable: bool, ambiguous: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.ambiguous = ambiguous


class SmtpAdapter:
    def __init__(
        self,
        host: str,
        port: int,
        security: SmtpSecurity,
        from_email: str,
        *,
        username: str = "",
        password: str = "",
        timeout_seconds: float = 10.0,
    ) -> None:
        self._host = host
        self._port = port
        self._security = security
        self._from_email = from_email
        self._username = username
        self._password = password
        self._timeout = timeout_seconds

    def send_message(
        self,
        recipient: str,
        subject: str,
        body: str,
        message_id: str,
    ) -> None:
        message = EmailMessage(policy=SMTP)
        message["From"] = self._from_email
        message["To"] = recipient
        message["Subject"] = subject
        message["Message-ID"] = message_id
        message.set_content(body)

        context = ssl.create_default_context()
        smtp: smtplib.SMTP | None = None
        try:
            if self._security == SmtpSecurity.TLS:
                smtp = smtplib.SMTP_SSL(
                    self._host,
                    self._port,
                    timeout=self._timeout,
                    context=context,
                )
            else:
                smtp = smtplib.SMTP(self._host, self._port, timeout=self._timeout)
                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()
            if self._username:
                smtp.login(self._username, self._password)
        except smtplib.SMTPServerDisconnected:
            _close_quietly(smtp)
            raise SmtpDeliveryError("smtp_connect_transient", retryable=True) from None
        except smtplib.SMTPException as error:
            _close_quietly(smtp)
            raise _definitive_error(error, "smtp_setup") from None
        except OSError:
            _close_quietly(smtp)
            raise SmtpDeliveryError("smtp_connect_transient", retryable=True) from None

        assert smtp is not None
        try:
            with smtp:
                smtp.send_message(message)
        except smtplib.SMTPServerDisconnected:
            raise SmtpDeliveryError(
                "smtp_delivery_ambiguous", retryable=False, ambiguous=True
            ) from None
        except smtplib.SMTPException as error:
            raise _definitive_error(error, "smtp_send") from None
        except OSError:
            raise SmtpDeliveryError(
                "smtp_delivery_ambiguous", retryable=False, ambiguous=True
            ) from None


def _close_quietly(smtp: smtplib.SMTP | None) -> None:
    if smtp is None:
        return
    with suppress(Exception):
        smtp.close()


def _definitive_error(error: smtplib.SMTPException, prefix: str) -> SmtpDeliveryError:
    if isinstance(error, smtplib.SMTPAuthenticationError):
        return SmtpDeliveryError("smtp_auth_rejected", retryable=False)
    if isinstance(error, smtplib.SMTPNotSupportedError):
        return SmtpDeliveryError("smtp_capability_missing", retryable=False)
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        codes = [value[0] for value in error.recipients.values()]
        retryable = bool(codes) and all(400 <= code < 500 for code in codes)
        return SmtpDeliveryError(
            "smtp_recipient_transient" if retryable else "smtp_recipient_rejected",
            retryable=retryable,
        )
    status = getattr(error, "smtp_code", 0)
    if 400 <= status < 500:
        return SmtpDeliveryError(f"{prefix}_transient", retryable=True)
    return SmtpDeliveryError(f"{prefix}_rejected", retryable=False)
