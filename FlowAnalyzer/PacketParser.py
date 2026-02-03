import binascii
import contextlib
import gzip
from typing import List, Optional, Tuple

from .logging_config import logger


class PacketParser:
    @staticmethod
    def process_batch(lines: List[str]) -> List[dict]:
        """
        批量处理行数据
        """
        results = []
        for line in lines:
            res = PacketParser.process_row(line)
            if res:
                results.append(res)
        return results

    @staticmethod
    def process_row(line: str) -> Optional[dict]:
        """
        解析 Tshark Lua 脚本输出的一行数据
        Columns:
        0: type ("req" / "rep" / "data")
        1: frame.number
        2: time_epoch
        3: header_hex
        4: file_data_hex (Body)
        5: uri_or_code
        6: request_in
        """
        try:
            parts = line.split("\t")
            if len(parts) < 6:
                return None

            p_type = parts[0]
            frame_num = int(parts[1])
            time_epoch = float(parts[2])

            # Hex string -> Bytes
            # parts[3] might be empty string
            header = binascii.unhexlify(parts[3]) if parts[3] else b""
            file_data = binascii.unhexlify(parts[4]) if parts[4] else b""

            uri_or_code = parts[5]
            request_in_str = parts[6] if len(parts) > 6 else ""

            if p_type == "req":
                return {"type": "request", "frame_num": frame_num, "header": header, "file_data": file_data, "time_epoch": time_epoch, "full_uri": uri_or_code, "request_in": None}
            elif p_type == "rep":
                request_in = int(request_in_str) if request_in_str else 0
                try:
                    status_code = int(uri_or_code)
                except (ValueError, TypeError):
                    status_code = 0

                return {
                    "type": "response",
                    "frame_num": frame_num,
                    "header": header,
                    "file_data": file_data,
                    "time_epoch": time_epoch,
                    "request_in": request_in,
                    "status_code": status_code,
                    "full_uri": "",
                }
            else:
                # 'data' or unknown, ignore for now based on current logic
                return None

        except Exception as e:
            logger.debug(f"Packet parse error: {e} | Line: {line[:100]}...")
            return None

    @staticmethod
    def split_http_headers(file_data: bytes) -> Tuple[bytes, bytes]:
        headerEnd = file_data.find(b"\r\n\r\n")
        if headerEnd != -1:
            return file_data[: headerEnd + 4], file_data[headerEnd + 4 :]

        headerEnd = file_data.find(b"\n\n")
        if headerEnd != -1:
            return file_data[: headerEnd + 2], file_data[headerEnd + 2 :]

        return b"", file_data

    @staticmethod
    def dechunk_http_response(file_data: bytes) -> bytes:
        """解码分块TCP数据"""
        if not file_data:
            return b""

        chunks = []
        cursor = 0
        total_len = len(file_data)

        while cursor < total_len:
            newline_idx = file_data.find(b"\n", cursor)
            if newline_idx == -1:
                # If no newline found, maybe it's just remaining data (though strictly should end with 0 chunk)
                # But for robustness we might perform a "best effort" or just stop.
                # raising ValueError("Not chunked data") might be too aggressive if we are just "trying" to dechunk
                # Let's assume non-chunked if strict format not found
                raise ValueError("Not chunked data")

            size_line = file_data[cursor:newline_idx].strip()
            # Handle chunk extension: ignore everything after ';'
            if b";" in size_line:
                size_line = size_line.split(b";", 1)[0].strip()

            if not size_line:
                cursor = newline_idx + 1
                continue

            try:
                chunk_size = int(size_line, 16)
            except ValueError:
                raise ValueError("Invalid chunk size")

            if chunk_size == 0:
                break

            data_start = newline_idx + 1
            data_end = data_start + chunk_size

            # Robustness check
            if data_start > total_len:
                break

            if data_end > total_len:
                chunks.append(file_data[data_start:])
                break

            chunks.append(file_data[data_start:data_end])

            cursor = data_end
            # Skip CRLF after chunk data
            while cursor < total_len and file_data[cursor] in (13, 10):
                cursor += 1

        return b"".join(chunks)

    @staticmethod
    def extract_http_file_data(full_request: bytes) -> Tuple[bytes, bytes]:
        """
        提取HTTP请求或响应中的文件数据 (混合模式 - 二进制优化版)
        """
        header = b""
        file_data = b""

        if not full_request:
            return b"", b""
        try:
            raw_bytes = binascii.unhexlify(full_request)
            header, body_part = PacketParser.split_http_headers(raw_bytes)

            with contextlib.suppress(Exception):
                body_part = PacketParser.dechunk_http_response(body_part)

            with contextlib.suppress(Exception):
                if body_part.startswith(b"\x1f\x8b"):
                    body_part = gzip.decompress(body_part)

            file_data = body_part
            return header, file_data

        except binascii.Error:
            logger.error("Hex转换失败")
            return b"", b""
        except Exception as e:
            logger.error(f"解析HTTP数据未知错误: {e}")
            return b"", b""
