from __future__ import annotations

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


path = "/run/offline-key/key.pem"
key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
payload = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
try:
    with os.fdopen(descriptor, "wb", closefd=False) as destination:
        destination.write(payload)
        destination.flush()
        os.fsync(destination.fileno())
finally:
    os.close(descriptor)
os.chown(path, 10001, 10001)
os.chmod(path, 0o600)
