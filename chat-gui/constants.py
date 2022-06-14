from enum import Enum

WINDOW_HEIGHT = 700
WINDOW_WIDTH = 700
WINDOWS_BG_COLOR = "#263D42"
LISTENER_PORT = 50001


class MessageType(Enum):
    handshake = 1
    handshakeAnswer = 2
    casualMessage = 3
    sendFile = 4
