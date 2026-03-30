"""
RemoteLink - Protocolo de Comunicação
"""

import json
import hashlib
import secrets
import time
from enum import Enum
from dataclasses import dataclass, asdict

PROTOCOL_VERSION = "1.0.0"
APP_NAME = "RemoteLink"
DEFAULT_RELAY_PORT = 8765
DEFAULT_WEB_PORT = 8080
HEARTBEAT_INTERVAL = 8
HEARTBEAT_TIMEOUT = 25
SCREEN_QUALITY = 50
SCREEN_FPS = 15
CHUNK_SIZE = 64 * 1024


class MessageType(str, Enum):
    REGISTER_AGENT = "register_agent"
    REGISTER_VIEWER = "register_viewer"
    AGENT_LIST = "agent_list"
    CONNECT_REQUEST = "connect_request"
    CONNECT_ACCEPT = "connect_accept"
    CONNECT_REJECT = "connect_reject"
    DISCONNECT = "disconnect"
    PING = "ping"
    PONG = "pong"
    SCREEN_FRAME = "screen_frame"
    SCREEN_REQUEST = "screen_request"
    SCREEN_CONFIG = "screen_config"
    MOUSE_EVENT = "mouse_event"
    KEYBOARD_EVENT = "keyboard_event"
    SHELL_START = "shell_start"
    SHELL_COMMAND = "shell_command"
    SHELL_INPUT = "shell_input"
    SHELL_OUTPUT = "shell_output"
    SHELL_RESIZE = "shell_resize"
    SHELL_STOP = "shell_stop"
    FILE_LIST_REQUEST = "file_list_request"
    FILE_LIST_RESPONSE = "file_list_response"
    FILE_DOWNLOAD_REQUEST = "file_download_request"
    FILE_UPLOAD_START = "file_upload_start"
    FILE_CHUNK = "file_chunk"
    FILE_COMPLETE = "file_complete"
    FILE_ERROR = "file_error"
    SYSTEM_INFO = "system_info"
    SYSTEM_INFO_REQUEST = "system_info_request"
    CONSOLE_START = "console_start"
    CONSOLE_FRAME = "console_frame"
    CONSOLE_INPUT = "console_input"
    CONSOLE_STOP  = "console_stop"
    ERROR = "error"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"


@dataclass
class Message:
    type: str
    data: dict = None
    session_id: str = None
    agent_id: str = None
    timestamp: float = None

    def __post_init__(self):
        if self.data is None:
            self.data = {}
        if self.timestamp is None:
            self.timestamp = time.time()

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

    @classmethod
    def from_json(cls, raw: str) -> 'Message':
        return cls(**json.loads(raw))


def generate_agent_id() -> str:
    return ''.join([str(secrets.randbelow(10)) for _ in range(9)])

def generate_session_id() -> str:
    return secrets.token_hex(16)

def generate_access_password(length: int = 6) -> str:
    return ''.join([str(secrets.randbelow(10)) for _ in range(length)])

def hash_password(password: str, salt: str = "") -> str:
    return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()

def create_message(msg_type, data=None, session_id=None, agent_id=None) -> str:
    msg = Message(
        type=msg_type.value if isinstance(msg_type, MessageType) else msg_type,
        data=data or {},
        session_id=session_id,
        agent_id=agent_id
    )
    return msg.to_json()

def parse_message(raw: str) -> Message:
    return Message.from_json(raw)
