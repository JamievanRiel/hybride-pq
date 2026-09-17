class PBP1Error(Exception):
    """Base class for every error raised by hybride_pq."""


class MalformedEncoding(PBP1Error):
    """A key or signature has the wrong magic, suite byte or length."""


class InvalidSignature(PBP1Error):
    """At least one of the two signature components does not verify."""


class KeystoreError(PBP1Error):
    """A keystore file is unreadable, malformed or uses unsupported parameters."""


class KeystoreDecryptError(KeystoreError):
    """Wrong passphrase or tampered keystore (deliberately indistinguishable)."""


class ChannelError(PBP1Error):
    """Handshake, framing or integrity failure on a secure channel."""
