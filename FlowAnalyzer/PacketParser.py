import binascii
from typing import List, Optional

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
