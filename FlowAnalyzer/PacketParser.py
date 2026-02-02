import binascii
import contextlib
import gzip
from typing import List, Optional, Tuple
from urllib import parse

from .logging_config import logger


class PacketParser:
    @staticmethod
    def parse_packet_data(row: list) -> Tuple[int, int, float, str, bytes]:
        """
        解析 Tshark 输出的一行数据
        row definition (all bytes):
        0: http.response.code
        1: http.request_in
        2: tcp.reassembled.data
        3: frame.number
        4: tcp.payload
        5: frame.time_epoch
        6: exported_pdu.exported_pdu
        7: http.request.full_uri 
        8: tcp.segment.count
        """
        frame_num = int(row[3])
        request_in = int(row[1]) if row[1] else frame_num
        # Decode only URI to string
        full_uri = parse.unquote(row[7].decode("utf-8", errors="replace")) if row[7] else ""
        time_epoch = float(row[5])

        # Logic for Raw Packet (Header Source)
        # Previous index 9 is now 8 since we removed http.file_data
        is_reassembled = len(row) > 8 and row[8]

        if is_reassembled and row[2]:
            full_request = row[2]
        elif row[4]:
            full_request = row[4]
        else:
            # Fallback (e.g. Exported PDU)
            full_request = row[2] if row[2] else (row[6] if row[6] else b"")

        return frame_num, request_in, time_epoch, full_uri, full_request

    @staticmethod
    def split_http_headers(file_data: bytes) -> Tuple[bytes, bytes]:
        headerEnd = file_data.find(b"\r\n\r\n")
        if headerEnd != -1:
            return file_data[: headerEnd + 4], file_data[headerEnd + 4 :]
        elif file_data.find(b"\n\n") != -1:
            headerEnd = file_data.index(b"\n\n") + 2
            return file_data[:headerEnd], file_data[headerEnd:]
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

    @staticmethod
    def process_row(line: bytes) -> Optional[dict]:
        """
        处理单行数据，返回结构化结果供主线程写入
        """
        line = line.rstrip(b"\r\n")
        if not line:
            return None

        row = line.split(b"\t")
        try:
            frame_num, request_in, time_epoch, full_uri, full_request = PacketParser.parse_packet_data(row)

            if not full_request:
                return None

            header, file_data = PacketParser.extract_http_file_data(full_request)

            # row[0] is http.response.code (bytes)
            is_response = bool(row[0])

            return {
                "type": "response" if is_response else "request",
                "frame_num": frame_num,
                "header": header,
                "file_data": file_data,
                "time_epoch": time_epoch,
                "request_in": request_in,  # Only useful for Response
                "full_uri": full_uri,  # Only useful for Request
            }

        except Exception:
            return None

    @staticmethod
    def process_batch(lines: List[bytes]) -> List[dict]:
        """
        批量处理行数据，减少函数调用开销
        """
        results = []
        for line in lines:
            res = PacketParser.process_row(line)
            if res:
                results.append(res)
        return results
