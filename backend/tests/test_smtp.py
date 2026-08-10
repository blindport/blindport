"""SMTP adapter message construction and sanitized failure classification."""

from __future__ import annotations

import smtplib
import ssl

import pytest

from blindport.adapters.smtp import SmtpAdapter, SmtpDeliveryError, SmtpSecurity


class _Smtp:
    instances: list[_Smtp] = []
    send_error: Exception | None = None
    login_error: Exception | None = None
    ehlo_error: Exception | None = None
    starttls_error: Exception | None = None

    def __init__(self, host: str, port: int, **kwargs) -> None:
        self.host = host
        self.port = port
        self.kwargs = kwargs
        self.events: list[object] = []
        self.__class__.instances.append(self)

    def ehlo(self) -> None:
        self.events.append("ehlo")
        if self.ehlo_error:
            raise self.ehlo_error

    def starttls(self, **kwargs) -> None:
        self.events.append(("starttls", kwargs))
        if self.starttls_error:
            raise self.starttls_error

    def login(self, username: str, password: str) -> None:
        self.events.append(("login", username, password))
        if self.login_error:
            raise self.login_error

    def send_message(self, message) -> None:
        if self.send_error:
            raise self.send_error
        self.events.append(("send", message))

    def __enter__(self):
        return self

    def __exit__(self, *args) -> None:
        return None

    def close(self) -> None:
        self.events.append("close")


@pytest.fixture(autouse=True)
def _smtp(monkeypatch):
    _Smtp.instances.clear()
    _Smtp.send_error = None
    _Smtp.login_error = None
    _Smtp.ehlo_error = None
    _Smtp.starttls_error = None
    monkeypatch.setattr(smtplib, "SMTP", _Smtp)
    monkeypatch.setattr(smtplib, "SMTP_SSL", _Smtp)


def _adapter(security: SmtpSecurity = SmtpSecurity.STARTTLS) -> SmtpAdapter:
    return SmtpAdapter(
        "mail.example.com",
        587,
        security,
        "notices@example.com",
        username="sender",
        password="secret",
        timeout_seconds=12,
    )


def test_starttls_adapter_sends_expected_message_after_authentication() -> None:
    _adapter().send_message(
        "person@example.net",
        "Expiry notice",
        "Renew soon.",
        "<stable@example.com>",
    )

    smtp = _Smtp.instances[0]
    assert smtp.host == "mail.example.com"
    assert smtp.kwargs["timeout"] == 12
    assert smtp.events[0] == "ehlo"
    assert smtp.events[1][0] == "starttls"
    assert isinstance(smtp.events[1][1]["context"], ssl.SSLContext)
    assert smtp.events[2] == "ehlo"
    assert smtp.events[3] == ("login", "sender", "secret")
    message = smtp.events[-1][1]
    assert message["From"] == "notices@example.com"
    assert message["To"] == "person@example.net"
    assert message["Message-ID"] == "<stable@example.com>"


def test_tls_adapter_supports_trusted_relay_without_credentials() -> None:
    adapter = SmtpAdapter("mail.example.com", 465, SmtpSecurity.TLS, "notices@example.com")
    adapter.send_message("person@example.net", "Notice", "Body", "<id@example.com>")
    smtp = _Smtp.instances[0]
    assert smtp.kwargs["timeout"] == 10.0
    assert isinstance(smtp.kwargs["context"], ssl.SSLContext)
    assert "ehlo" not in smtp.events
    assert not any(
        isinstance(event, tuple) and event[0] in {"starttls", "login"} for event in smtp.events
    )


@pytest.mark.parametrize(
    "stage,error,code,retryable",
    [
        (
            "ehlo_error",
            smtplib.SMTPResponseException(421, b"private"),
            "smtp_setup_transient",
            True,
        ),
        (
            "starttls_error",
            smtplib.SMTPNotSupportedError("private capability"),
            "smtp_capability_missing",
            False,
        ),
        (
            "login_error",
            smtplib.SMTPAuthenticationError(535, b"private"),
            "smtp_auth_rejected",
            False,
        ),
    ],
)
def test_setup_stages_close_and_classify_without_private_text(
    stage: str, error: Exception, code: str, retryable: bool
) -> None:
    setattr(_Smtp, stage, error)

    with pytest.raises(SmtpDeliveryError) as exc_info:
        _adapter().send_message("private@example.net", "Notice", "Body", "<id@example.com>")

    assert exc_info.value.code == code
    assert exc_info.value.retryable is retryable
    assert exc_info.value.ambiguous is False
    assert _Smtp.instances[0].events[-1] == "close"
    assert "private" not in str(exc_info.value)


def test_setup_failure_closes_connection_and_sanitizes_error() -> None:
    _Smtp.login_error = smtplib.SMTPAuthenticationError(535, b"private response")

    with pytest.raises(SmtpDeliveryError) as exc_info:
        _adapter().send_message("private@example.net", "Notice", "Body", "<id@example.com>")

    assert exc_info.value.code == "smtp_auth_rejected"
    assert _Smtp.instances[0].events[-1] == "close"
    assert "private" not in str(exc_info.value)


@pytest.mark.parametrize(
    "error,code,retryable,ambiguous",
    [
        (
            smtplib.SMTPRecipientsRefused({"private@example.net": (450, b"later")}),
            "smtp_recipient_transient",
            True,
            False,
        ),
        (
            smtplib.SMTPRecipientsRefused({"private@example.net": (550, b"no")}),
            "smtp_recipient_rejected",
            False,
            False,
        ),
        (smtplib.SMTPDataError(451, b"later"), "smtp_send_transient", True, False),
        (smtplib.SMTPDataError(554, b"rejected"), "smtp_send_rejected", False, False),
        (
            smtplib.SMTPServerDisconnected("private response"),
            "smtp_delivery_ambiguous",
            False,
            True,
        ),
        (TimeoutError("private timeout"), "smtp_delivery_ambiguous", False, True),
    ],
)
def test_send_failures_are_classified_without_exposing_server_or_recipient(
    error: Exception, code: str, retryable: bool, ambiguous: bool
) -> None:
    _Smtp.send_error = error
    with pytest.raises(SmtpDeliveryError) as exc_info:
        _adapter().send_message(
            "private@example.net", "Private subject", "Private body", "<id@example.com>"
        )
    assert exc_info.value.code == code
    assert exc_info.value.retryable is retryable
    assert exc_info.value.ambiguous is ambiguous
    assert exc_info.value.__cause__ is None
    assert "private" not in str(exc_info.value)
