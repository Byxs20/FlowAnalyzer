import os
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, Optional

from .logging_config import logger
from .Models import HttpPair, Request, Response
from .PacketParser import PacketParser
from .Path import get_default_tshark_path


class FlowAnalyzer:
    """
    FlowAnalyzer 流量分析器 (智能缓存版)
    特点：
    1. Tshark -> Pipe -> ThreadPool -> SQLite
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
                req = Request(frame_num=row[0], header=row[1] or b"", file_data=row[2] or b"", full_uri=row[3] or "", time_epoch=row[4])

                resp = None
                if row[5] is not None:
                    resp = Response(frame_num=row[5], header=row[6] or b"", file_data=row[7] or b"", time_epoch=row[8], _request_in=row[9])

                yield HttpPair(request=req, response=resp)

            # === 第二步：孤儿响应查询 ===
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
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError("流量包路径不存在：%s" % file_path)

        abs_file_path = os.path.abspath(file_path)
        pcap_dir = os.path.dirname(abs_file_path)
        base_name = os.path.splitext(os.path.basename(abs_file_path))[0]
        db_path = os.path.join(pcap_dir, f"{base_name}.db")

        if FlowAnalyzer._is_cache_valid(db_path, abs_file_path, display_filter):
            logger.debug(f"缓存校验通过 (Filter匹配且文件未变)，使用缓存: [{db_path}]")
            return db_path
        else:
            logger.debug(f"缓存失效或不存在 (Filter变更或文件更新)，开始重新解析...")

        tshark_path = FlowAnalyzer.get_tshark_path(tshark_path)
        FlowAnalyzer._stream_tshark_to_db(abs_file_path, display_filter, tshark_path, db_path)

        return db_path

    @staticmethod
    def get_db_data(file_path: str, display_filter: str, tshark_path: Optional[str] = None) -> str:
        return FlowAnalyzer.get_json_data(file_path, display_filter, tshark_path)

    @staticmethod
    def _is_cache_valid(db_path: str, pcap_path: str, current_filter: str) -> bool:
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
        """流式解析并存入DB (多线程版)"""
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
            "fields",
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
            "-e",
            "http.file_data",  # 8
            "-e",
            "tcp.segment.count",  # 9
            "-E",
            "header=n",
            "-E",
            "separator=/t",
            "-E",
            "quote=n",
            "-E",
            "occurrence=f",
        ]

        logger.debug(f"执行 Tshark: {command}")
        BATCH_SIZE = 2000
        MAX_PENDING_BATCHES = 20  # 控制内存中待处理的批次数量 (Backpressure)

        # 使用 ThreadPoolExecutor 并行处理数据
        max_workers = min(32, (os.cpu_count() or 1) + 4)

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=os.path.dirname(os.path.abspath(pcap_path)))
        try:
            with sqlite3.connect(db_path) as conn:
                cursor = conn.cursor()

                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    current_batch = []
                    pending_futures = []  # List[Future]

                    def write_results_to_db(results):
                        """将一批处理好的结果写入数据库"""
                        if not results:
                            return

                        db_req_rows = []
                        db_resp_rows = []

                        for item in results:
                            if item["type"] == "response":
                                db_resp_rows.append((item["frame_num"], item["header"], item["file_data"], item["time_epoch"], item["request_in"]))
                            else:
                                db_req_rows.append((item["frame_num"], item["header"], item["file_data"], item["full_uri"], item["time_epoch"]))

                        if db_req_rows:
                            cursor.executemany("INSERT OR REPLACE INTO requests VALUES (?,?,?,?,?)", db_req_rows)
                        if db_resp_rows:
                            cursor.executemany("INSERT OR REPLACE INTO responses VALUES (?,?,?,?,?)", db_resp_rows)

                    def submit_batch():
                        """提交当前批次到线程池"""
                        if not current_batch:
                            return

                        # Copy batch data for the thread (list slicing is fast)
                        batch_data = current_batch[:]
                        future = executor.submit(PacketParser.process_batch, batch_data)
                        pending_futures.append(future)
                        current_batch.clear()

                    # --- Main Pipeline Loop ---
                    if process.stdout:
                        for line in process.stdout:
                            current_batch.append(line)

                            if len(current_batch) >= BATCH_SIZE:
                                submit_batch()

                                # Backpressure: 如果积压的任务太多，主线程暂停读取，先处理掉最早的一个
                                # 这样既保证了 Pipeline 流动，又防止内存爆掉
                                if len(pending_futures) >= MAX_PENDING_BATCHES:
                                    oldest_future = pending_futures.pop(0)
                                    write_results_to_db(oldest_future.result())

                    # --- Drain Pipeline ---
                    # 提交剩余数据
                    submit_batch()

                    # 等待所有剩余任务完成
                    for future in pending_futures:
                        write_results_to_db(future.result())

                # 创建索引和元数据
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

    @staticmethod
    def get_tshark_path(tshark_path: Optional[str]) -> str:
        default_tshark_path = get_default_tshark_path()
        use_path = tshark_path if tshark_path and os.path.exists(tshark_path) else default_tshark_path
        if not use_path or not os.path.exists(use_path):
            logger.critical("未找到 Tshark，请检查路径配置")
            exit(-1)
        return use_path
