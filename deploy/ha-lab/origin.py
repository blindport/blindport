from __future__ import annotations

import datetime
import socket
import ssl
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ha.relay.test")])
now = datetime.datetime.now(datetime.UTC)
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(subject)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(minutes=1))
    .not_valid_after(now + datetime.timedelta(days=1))
    .add_extension(x509.SubjectAlternativeName([x509.DNSName("ha.relay.test")]), False)
    .sign(key, hashes.SHA256())
)

with tempfile.TemporaryDirectory() as directory:
    cert_path = Path(directory, "cert.pem")
    key_path = Path(directory, "key.pem")
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    with socket.create_server(("0.0.0.0", 8443)) as listener:
        while True:
            connection, _ = listener.accept()
            try:
                with context.wrap_socket(connection, server_side=True) as tls:
                    tls.recv(8192)
                    body = b"ha-origin\n"
                    tls.sendall(
                        b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: "
                        + str(len(body)).encode("ascii")
                        + b"\r\n\r\n"
                        + body
                    )
            except (ConnectionError, ssl.SSLError):
                connection.close()
