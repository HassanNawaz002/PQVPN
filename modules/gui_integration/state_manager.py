"""Connection state must only advance after verified tunnel setup."""
from enum import Enum
class ConnectionState(str, Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"
