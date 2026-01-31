from dataclasses import dataclass
from typing import NamedTuple, Optional


@dataclass
class Request:
    __slots__ = ("frame_num", "header", "file_data", "full_uri", "time_epoch")
    frame_num: int
    header: bytes
    file_data: bytes
    full_uri: str
    time_epoch: float


@dataclass
class Response:
    __slots__ = ("frame_num", "header", "file_data", "time_epoch", "_request_in")
    frame_num: int
    header: bytes
    file_data: bytes
    time_epoch: float
    _request_in: Optional[int]


class HttpPair(NamedTuple):
    request: Optional[Request]
    response: Optional[Response]
