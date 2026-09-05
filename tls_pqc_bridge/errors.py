class BridgeError(Exception):
    """Base class for failures that must terminate a bridge connection."""


class ConfigurationError(BridgeError):
    """A local credential or invocation is invalid."""


class ProtocolError(BridgeError):
    """A peer message violates the protocol grammar or state machine."""


class AuthenticationError(BridgeError):
    """Peer authentication or key confirmation failed."""


class IntegrityError(BridgeError):
    """An authenticated record or transferred payload failed validation."""
