from dataclasses import dataclass
from typing import NamedTuple, Optional


@dataclass
class Request:
    __slots__ = ("frame_num", "header", "file_data", "full_uri", "time_epoch")
    frame_num: int
    header: bytes
    file_data: bytes
    time_epoch: float
    full_uri: str


@dataclass
class Response:
    __slots__ = ("frame_num", "header", "file_data", "time_epoch", "status_code", "_request_in")
    frame_num: int
    header: bytes
    file_data: bytes
    time_epoch: float
    status_code: int
    _request_in: Optional[int]


class HttpPair(NamedTuple):
    request: Optional[Request]
    response: Optional[Response]
