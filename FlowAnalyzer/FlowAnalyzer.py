import contextlib
import csv
import gzip
import os
import sqlite3
import subprocess
from dataclasses import dataclass
from typing import Iterable, NamedTuple, Optional, Tuple
from urllib import parse

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
    1. Tshark -> Pipe -> CSV -> SQLite (无中间JSON文件)
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

    def generate_http_dict_pairs(self) -> Iterable[HttpPair]:
        """生成HTTP请求和响应信息的字典对 (SQL JOIN 高性能版)"""
        if not os.path.exists(self.db_path):
            return

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # 开启查询优化
            cursor.execute("PRAGMA query_only = 1;")

            # === 第一步：配对查询 ===
            # 利用 SQLite 的 LEFT JOIN 直接匹配请求和响应
            # 避免将所有数据加载到 Python 内存中
            sql_pair = """
            SELECT 
                req.frame_num, req.header, req.file_data, req.full_uri, req.time_epoch,  -- 0-4 (Request)
                resp.frame_num, resp.header, resp.file_data, resp.time_epoch, resp.request_in -- 5-9 (Response)
            FROM requests req
            LEFT JOIN responses resp ON req.frame_num = resp.request_in
            ORDER BY req.frame_num ASC
            """

            cursor.execute(sql_pair)

            # 流式遍历结果，内存占用极低
            for row in cursor:
                # 构建 Request 对象
                # 注意处理 NULL 情况，虽然 requests 表理论上不为空，但防万一用 or b''
                req = Request(frame_num=row[0], header=row[1] or b"", file_data=row[2] or b"", full_uri=row[3] or "", time_epoch=row[4])

                resp = None
                # 如果 row[5] (Response frame_num) 不为空，说明匹配到了响应
                if row[5] is not None:
                    resp = Response(frame_num=row[5], header=row[6] or b"", file_data=row[7] or b"", time_epoch=row[8], _request_in=row[9])

                yield HttpPair(request=req, response=resp)

            # === 第二步：孤儿响应查询 ===
            # 找出那些有 request_in 但找不到对应 Request 的响应包
            sql_orphan = """
            SELECT frame_num, header, file_data, time_epoch, request_in
            FROM responses
            WHERE request_in NOT IN (SELECT frame_num FROM requests)
            """
            cursor.execute(sql_orphan)

            for row in cursor:
                resp = Response(frame_num=row[0], header=row[1] or b"", file_data=row[2] or b"", time_epoch=row[3], _request_in=row[4])
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
        # 增加 CSV 字段大小限制，防止超大包报错
        # 将限制设置为系统最大值，注意 32位系统不要超过 2GB (但 Python int通常是动态的，保险起见设大一点)
        try:
            csv.field_size_limit(500 * 1024 * 1024)  # 500MB
        except Exception:
            # 如果失败，尝试取最大值
            csv.field_size_limit(int(2**31 - 1))

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

        # 修改命令为 -T fields 模式
        command = [
            tshark_path,
            "-r",
            pcap_path,
            "-Y",
            f"({display_filter})",
            "-T",
            "fields",
            # 指定输出字段
            "-e",
            "http.response.code",  # 0
            "-e",
            "http.request_in",  # 1
            "-e",
            "tcp.reassembled.data",  # 2
            "-e",
            "frame.number",  # 3
            "-e",
            "tcp.payload",  # 4
            "-e",
            "frame.time_epoch",  # 5
            "-e",
            "exported_pdu.exported_pdu",  # 6
            "-e",
            "http.request.full_uri",  # 7
            # 格式控制
            "-E",
            "header=n",  # 不输出表头
            "-E",
            "separator=|",  # 使用 | 分割 (比逗号更安全)
            "-E",
            "quote=d",  # 双引号包裹
            "-E",
            "occurrence=f",  # 每个字段只取第一个值 (First)
        ]

        logger.debug(f"执行 Tshark: {command}")

        # 使用 utf-8 编码读取 stdout text mode
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=os.path.dirname(os.path.abspath(pcap_path)), encoding="utf-8", errors="replace")

        db_req_rows = []
        db_resp_rows = []
        BATCH_SIZE = 5000

        try:
            # 使用 csv.reader 解析 stdout 流
            reader = csv.reader(process.stdout, delimiter="|", quotechar='"')  # type: ignore
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()

                for row in reader:
                    # row 是一个列表，对应上面的 -e 顺序
                    # [code, req_in, reassembled, frame, payload, epoch, pdu, uri]
                    if not row:
                        continue

                    try:
                        # 解析数据
                        frame_num, request_in, time_epoch, full_uri, full_request = FlowAnalyzer.parse_packet_data(row)

                        if not full_request:
                            continue

                        header, file_data = FlowAnalyzer.extract_http_file_data(full_request)

                        # 判断是请求还是响应
                        # http.response.code (index 0) 是否为空
                        if row[0]:
                            # Response
                            db_resp_rows.append((frame_num, header, file_data, time_epoch, request_in))
                        else:
                            # Request
                            db_req_rows.append((frame_num, header, file_data, full_uri, time_epoch))

                        # 批量插入
                        if len(db_req_rows) >= BATCH_SIZE:
                            cursor.executemany("INSERT OR REPLACE INTO requests VALUES (?,?,?,?,?)", db_req_rows)
                            db_req_rows.clear()
                        if len(db_resp_rows) >= BATCH_SIZE:
                            cursor.executemany("INSERT OR REPLACE INTO responses VALUES (?,?,?,?,?)", db_resp_rows)
                            db_resp_rows.clear()

                    except Exception as e:
                        # 偶尔可能会有解析失败的行，跳过即可
                        pass

                # 插入剩余数据
                if db_req_rows:
                    cursor.executemany("INSERT OR REPLACE INTO requests VALUES (?,?,?,?,?)", db_req_rows)
                if db_resp_rows:
                    cursor.executemany("INSERT OR REPLACE INTO responses VALUES (?,?,?,?,?)", db_resp_rows)

                # --- 优化点：插入完数据后再创建索引，速度更快 ---
                cursor.execute("CREATE INDEX idx_resp_req_in ON responses(request_in)")

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
    def parse_packet_data(row: list) -> Tuple[int, int, float, str, str]:
        # row definition:
        # 0: http.response.code
        # 1: http.request_in
        # 2: tcp.reassembled.data
        # 3: frame.number
        # 4: tcp.payload
        # 5: frame.time_epoch
        # 6: exported_pdu.exported_pdu
        # 7: http.request.full_uri

        frame_num = int(row[3])
        request_in = int(row[1]) if row[1] else frame_num
        full_uri = parse.unquote(row[7]) if row[7] else ""
        time_epoch = float(row[5])

        if row[2]:
            full_request = row[2]
        elif row[4]:
            full_request = row[4]
        else:
            full_request = row[6] if row[6] else ""

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
        """解码分块TCP数据"""
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
