import contextlib
import gzip
import os
import sqlite3
import subprocess
from dataclasses import dataclass
from typing import Dict, Iterable, NamedTuple, Optional, Tuple
from urllib import parse

import ijson

from .logging_config import logger
from .Path import get_default_tshark_path


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


class FlowAnalyzer:
    """
    FlowAnalyzer 流量分析器 (智能缓存版)
    特点：
    1. Tshark -> Pipe -> ijson -> SQLite (无中间JSON文件)
    2. 智能校验：自动比对 Filter 和文件修改时间，防止缓存错乱
    3. 存储优化：数据库文件生成在流量包同级目录下
    """

    def __init__(self, db_path: str):
        """
        初始化 FlowAnalyzer
        :param db_path: 数据库文件路径 (由 get_json_data 返回)
        """
        # 路径兼容处理
        if db_path.endswith(".json"):
            possible_db = db_path + ".db"
            if os.path.exists(possible_db):
                self.db_path = possible_db
            else:
                self.db_path = db_path
        else:
            self.db_path = db_path

        self.check_db_file()

    def check_db_file(self):
        """检查数据库文件是否存在"""
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(f"未找到数据文件或缓存数据库: {self.db_path}，请先调用 get_json_data 生成。")

    def _load_from_db(self) -> Tuple[Dict[int, Request], Dict[int, Response]]:
        """从 SQLite 数据库加载数据"""
        requests, responses = {}, {}
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()

                # 简单防错检查
                try:
                    cursor.execute("SELECT count(*) FROM requests")
                    if cursor.fetchone()[0] == 0:
                        cursor.execute("SELECT count(*) FROM responses")
                        if cursor.fetchone()[0] == 0:
                            return {}, {}
                except sqlite3.OperationalError:
                    logger.error("数据库损坏或表不存在")
                    return {}, {}

                logger.debug(f"正在加载缓存数据: {self.db_path}")

                # 加载 Requests
                cursor.execute("SELECT frame_num, header, file_data, full_uri, time_epoch FROM requests")
                for row in cursor.fetchall():
                    requests[row[0]] = Request(row[0], row[1], row[2], row[3], row[4])

                # 加载 Responses
                cursor.execute("SELECT frame_num, header, file_data, time_epoch, request_in FROM responses")
                for row in cursor.fetchall():
                    responses[row[0]] = Response(row[0], row[1], row[2], row[3], row[4])

                return requests, responses
        except sqlite3.Error as e:
            logger.error(f"读取数据库出错: {e}")
            return {}, {}

    def generate_http_dict_pairs(self) -> Iterable[HttpPair]:
        """生成HTTP请求和响应信息的字典对"""
        requests, responses = self._load_from_db()
        response_map = {r._request_in: r for r in responses.values()}
        yielded_resps = set()

        for req_id, req in requests.items():
            resp = response_map.get(req_id)
            if resp:
                yielded_resps.add(resp.frame_num)
                yield HttpPair(request=req, response=resp)
            else:
                yield HttpPair(request=req, response=None)

        for resp in responses.values():
            if resp.frame_num not in yielded_resps:
                yield HttpPair(request=None, response=resp)

    # =========================================================================
    #  静态方法区域：包含校验逻辑和流式处理
    # =========================================================================

    @staticmethod
    def get_json_data(file_path: str, display_filter: str, tshark_path: Optional[str] = None) -> str:
        """
        获取数据路径 (智能校验版)。

        逻辑：
        1. 根据 PCAP 路径推算 DB 路径 (位于 PCAP 同级目录)。
        2. 检查 DB 是否存在。
        3. 检查 Filter 和文件元数据是否一致。
        4. 若一致返回路径，不一致则重新解析。
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError("流量包路径不存在：%s" % file_path)

        # --- 修改处：获取流量包的绝对路径和所在目录 ---
        abs_file_path = os.path.abspath(file_path)
        pcap_dir = os.path.dirname(abs_file_path)  # 获取文件所在的文件夹
        base_name = os.path.splitext(os.path.basename(abs_file_path))[0]

        # 将 db_path 拼接在流量包所在的目录下
        db_path = os.path.join(pcap_dir, f"{base_name}.db")
        # ----------------------------------------

        # --- 校验环节 ---
        if FlowAnalyzer._is_cache_valid(db_path, abs_file_path, display_filter):
            logger.debug(f"缓存校验通过 (Filter匹配且文件未变)，使用缓存: [{db_path}]")
            return db_path
        else:
            logger.debug(f"缓存失效或不存在 (Filter变更或文件更新)，开始重新解析...")

        # --- 解析环节 ---
        tshark_path = FlowAnalyzer.get_tshark_path(tshark_path)
        FlowAnalyzer._stream_tshark_to_db(abs_file_path, display_filter, tshark_path, db_path)

        return db_path

    @staticmethod
    def get_db_data(file_path: str, display_filter: str, tshark_path: Optional[str] = None) -> str:
        """
        获取数据库路径 (get_json_data 的语义化别名)。
        新项目建议使用此方法名，get_json_data 保留用于兼容旧习惯。
        """
        return FlowAnalyzer.get_json_data(file_path, display_filter, tshark_path)

    @staticmethod
    def _is_cache_valid(db_path: str, pcap_path: str, current_filter: str) -> bool:
        """
        检查缓存有效性：对比 Filter 字符串和文件元数据
        """
        if not os.path.exists(db_path) or os.path.getsize(db_path) == 0:
            return False

        try:
            current_mtime = os.path.getmtime(pcap_path)
            current_size = os.path.getsize(pcap_path)

            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT filter, pcap_mtime, pcap_size FROM meta_info LIMIT 1")
                row = cursor.fetchone()

                if not row:
                    return False

                cached_filter, cached_mtime, cached_size = row

                # 容差 0.1秒
                if cached_filter == current_filter and cached_size == current_size and abs(cached_mtime - current_mtime) < 0.1:
                    return True
                else:
                    logger.debug(f"校验失败: 缓存Filter={cached_filter} vs 当前={current_filter}")
                    return False

        except sqlite3.OperationalError:
            return False
        except Exception as e:
            logger.warning(f"缓存校验出错: {e}，将重新解析")
            return False

    @staticmethod
    def _stream_tshark_to_db(pcap_path: str, display_filter: str, tshark_path: str, db_path: str):
        """流式解析并存入DB，同时记录元数据"""

        if os.path.exists(db_path):
            os.remove(db_path)

        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA synchronous = OFF")
            cursor.execute("PRAGMA journal_mode = MEMORY")

            cursor.execute("CREATE TABLE requests (frame_num INTEGER PRIMARY KEY, header BLOB, file_data BLOB, full_uri TEXT, time_epoch REAL)")
            cursor.execute("CREATE TABLE responses (frame_num INTEGER PRIMARY KEY, header BLOB, file_data BLOB, time_epoch REAL, request_in INTEGER)")

            cursor.execute("""
                CREATE TABLE meta_info (
                    id INTEGER PRIMARY KEY, 
                    filter TEXT, 
                    pcap_path TEXT, 
                    pcap_mtime REAL, 
                    pcap_size INTEGER
                )
            """)
            conn.commit()

        command = [
            tshark_path,
            "-r",
            pcap_path,
            "-Y",
            f"({display_filter})",
            "-T",
            "json",
            "-e",
            "http.response.code",
            "-e",
            "http.request_in",
            "-e",
            "tcp.reassembled.data",
            "-e",
            "frame.number",
            "-e",
            "tcp.payload",
            "-e",
            "frame.time_epoch",
            "-e",
            "exported_pdu.exported_pdu",
            "-e",
            "http.request.full_uri",
        ]

        logger.debug(f"执行 Tshark: {command}")

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=os.path.dirname(os.path.abspath(pcap_path)))

        db_req_rows = []
        db_resp_rows = []
        BATCH_SIZE = 5000

        try:
            parser = ijson.items(process.stdout, "item")

            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()

                for packet in parser:
                    layers = packet.get("_source", {}).get("layers", {})
                    if not layers:
                        continue

                    try:
                        frame_num, request_in, time_epoch, full_uri, full_request = FlowAnalyzer.parse_packet_data(layers)
                        if not full_request:
                            continue
                        header, file_data = FlowAnalyzer.extract_http_file_data(full_request)

                        if layers.get("http.response.code"):
                            db_resp_rows.append((frame_num, header, file_data, time_epoch, request_in))
                        else:
                            db_req_rows.append((frame_num, header, file_data, full_uri, time_epoch))

                        if len(db_req_rows) >= BATCH_SIZE:
                            cursor.executemany("INSERT OR REPLACE INTO requests VALUES (?,?,?,?,?)", db_req_rows)
                            db_req_rows.clear()
                        if len(db_resp_rows) >= BATCH_SIZE:
                            cursor.executemany("INSERT OR REPLACE INTO responses VALUES (?,?,?,?,?)", db_resp_rows)
                            db_resp_rows.clear()

                    except Exception:
                        pass

                if db_req_rows:
                    cursor.executemany("INSERT OR REPLACE INTO requests VALUES (?,?,?,?,?)", db_req_rows)
                if db_resp_rows:
                    cursor.executemany("INSERT OR REPLACE INTO responses VALUES (?,?,?,?,?)", db_resp_rows)

                pcap_mtime = os.path.getmtime(pcap_path)
                pcap_size = os.path.getsize(pcap_path)
                cursor.execute("INSERT INTO meta_info (filter, pcap_path, pcap_mtime, pcap_size) VALUES (?, ?, ?, ?)", (display_filter, pcap_path, pcap_mtime, pcap_size))

                conn.commit()

        except Exception as e:
            logger.error(f"解析错误: {e}")
            if process.poll() is None:
                process.terminate()
        finally:
            if process.poll() is None:
                process.terminate()

    # --- 辅助静态方法 ---

    @staticmethod
    def parse_packet_data(packet: dict) -> Tuple[int, int, float, str, str]:
        frame_num = int(packet["frame.number"][0])
        request_in = int(packet["http.request_in"][0]) if packet.get("http.request_in") else frame_num
        full_uri = parse.unquote(packet["http.request.full_uri"][0]) if packet.get("http.request.full_uri") else ""
        time_epoch = float(packet["frame.time_epoch"][0])

        if packet.get("tcp.reassembled.data"):
            full_request = packet["tcp.reassembled.data"][0]
        elif packet.get("tcp.payload"):
            full_request = packet["tcp.payload"][0]
        else:
            full_request = packet["exported_pdu.exported_pdu"][0] if packet.get("exported_pdu.exported_pdu") else ""
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
    def dechunck_http_response(file_data: bytes) -> bytes:
        """解码分块TCP数据 (修复版)
        注意：如果数据不是 Chunked 格式，此函数必须抛出异常，
        以便外层逻辑回退到使用原始数据。
        """
        if not file_data:
            return b""

        chunks = []
        cursor = 0
        total_len = len(file_data)

        while cursor < total_len:
            # 1. 寻找当前 Chunk Size 行的结束符 (\n)
            newline_idx = file_data.find(b"\n", cursor)
            if newline_idx == -1:
                # 找不到换行符，说明格式不对，抛出异常让外层处理
                raise ValueError("Not chunked data")

            # 2. 提取并解析十六进制大小
            size_line = file_data[cursor:newline_idx].strip()

            # 处理可能的空行 (例如上一个 Chunk 后的 CRLF)
            if not size_line:
                cursor = newline_idx + 1
                continue

            # 这里不要捕获 ValueError，如果解析失败，直接抛出
            # 说明这根本不是 chunk size，而是普通数据
            chunk_size = int(size_line, 16)

            # Chunk Size 为 0 表示传输结束
            if chunk_size == 0:
                break

            # 3. 定位数据区域
            data_start = newline_idx + 1
            data_end = data_start + chunk_size

            if data_end > total_len:
                # 数据被截断，尽力读取
                chunks.append(file_data[data_start:])
                break

            # 4. 提取数据
            chunks.append(file_data[data_start:data_end])

            # 5. 移动游标
            cursor = data_end
            # 跳过尾随的 \r 和 \n
            while cursor < total_len and file_data[cursor] in (13, 10):
                cursor += 1

        return b"".join(chunks)

    @staticmethod
    def extract_http_file_data(full_request: str) -> Tuple[bytes, bytes]:
        """提取HTTP请求或响应中的文件数据 (修复版)"""
        # 1. 基础校验
        if not full_request:
            return b"", b""

        try:
            # 转为二进制
            raw_bytes = bytes.fromhex(full_request)

            # 分割 Header 和 Body
            header, file_data = FlowAnalyzer.split_http_headers(raw_bytes)

            # 处理 Chunked 编码
            with contextlib.suppress(Exception):
                file_data = FlowAnalyzer.dechunck_http_response(file_data)

            # 处理 Gzip 压缩
            with contextlib.suppress(Exception):
                if file_data.startswith(b"\x1f\x8b"):
                    file_data = gzip.decompress(file_data)

            return header, file_data

        except ValueError as e:
            # 专门捕获 Hex 转换错误，并打印出来，方便你调试
            # 如果你在控制台看到这个错误，说明 Tshark 输出的数据格式非常奇怪
            logger.error(f"Hex转换失败: {str(e)[:100]}... 原数据片段: {full_request[:50]}")
            return b"", b""
        except Exception as e:
            logger.error(f"解析HTTP数据未知错误: {e}")
            return b"", b""

    @staticmethod
    def get_tshark_path(tshark_path: Optional[str]) -> str:
        default_tshark_path = get_default_tshark_path()
        use_path = tshark_path if tshark_path and os.path.exists(tshark_path) else default_tshark_path
        if not use_path or not os.path.exists(use_path):
            logger.critical("未找到 Tshark，请检查路径配置")
            exit(-1)
        return use_path
