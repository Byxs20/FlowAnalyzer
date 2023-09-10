import os
import json
import gzip
import contextlib
import subprocess
from typing import Tuple


class FlowAnalyzer:
    """FlowAnalyzer是一个流量分析器，用于解析和处理tshark导出的JSON数据文件"""

    def __init__(self, jsonPath: str):
        """初始化FlowAnalyzer对象

        Parameters
        ----------
        jsonPath : str
            tshark导出的JSON文件路径
        """
        self.jsonPath = jsonPath
        self.check_json_file()

    def check_json_file(self):
        # sourcery skip: remove-redundant-fstring, replace-interpolation-with-fstring
        """检查JSON文件是否存在并非空

        Raises
        ------
        FileNotFoundError
            当JSON文件不存在时抛出异常
        ValueError
            当JSON文件内容为空时抛出异常
        """
        if not os.path.exists(self.jsonPath):
            raise FileNotFoundError(
                f"您的tshark导出的JSON文件没有找到！JSON路径：%s" % self.jsonPath)

        if os.path.getsize(self.jsonPath) == 0:
            raise ValueError("您的tshark导出的JSON文件内容为空！JSON路径：%s" % self.jsonPath)

    def parse_http_json(self) -> Tuple[dict, list]:
        # sourcery skip: use-named-expression
        """解析JSON数据文件中的HTTP请求和响应信息

        Returns
        -------
        tuple
            包含请求字典和响应列表的元组
        """
        with open(self.jsonPath, "r") as f:
            data = json.load(f)

        requests, responses = {}, {}
        for packet in data:
            packet = packet["_source"]["layers"]
            time_epoch = float(packet["frame.time_epoch"][0]) if packet.get("frame.time_epoch") else None
            full_request = packet["tcp.reassembled.data"][0] if packet.get("tcp.reassembled.data") else packet["tcp.payload"][0]
            frame_num = int(packet["frame.number"][0]) if packet.get("frame.number") else None
            request_in = int(packet["http.request_in"][0]) if packet.get("http.request_in") else frame_num
            header, file_data = self.extract_http_file_data(full_request)
            
            if packet.get("http.response_number"):
                responses[frame_num] = {"frame_num": frame_num, "request_in": request_in, "header": header, "file_data": file_data, "time_epoch": time_epoch}
            else:
                requests[frame_num] = {"frame_num": frame_num, "header": header, "file_data": file_data, "time_epoch": time_epoch}
        return requests, responses

    def generate_http_dict_pairs(self):  # sourcery skip: use-named-expression
        """生成HTTP请求和响应信息的字典对
        Yields
        ------
        Iterator[dict]
            包含请求和响应信息的字典迭代器
        """
        requests, responses = self.parse_http_json()
        response_map = {r['request_in']: r for r in responses.values()}
        yielded_resps = []
        for req_id, req in requests.items():
            resp = response_map.get(req_id)
            if resp:
                yielded_resps.append(resp)
                del resp['request_in']
                yield {'request': req, 'response': resp}
            else:
                yield {'request': req}

        for resp in response_map.values():
            if resp not in yielded_resps:
                del resp['request_in']
                yield {'response': resp}

    @staticmethod
    def get_json_data(filePath, display_filter):
        """获取JSON数据并保存至文件，保存目录是当前工作目录，也就是您运行脚本所在目录

        Parameters
        ----------
        filePath : str
            待处理的数据文件路径
        display_filter : str
            WireShark的显示过滤器

        Returns
        -------
        str
            保存JSON数据的文件路径
        """
        # sourcery skip: use-fstring-for-formatting
        jsonPath = os.path.join(os.getcwd(), "output.json")
        command = 'tshark -r {} -Y "{}" -T json -e http.request_number -e http.response_number -e http.request_in -e tcp.reassembled.data -e frame.number -e tcp.payload -e frame.time_epoch > {}'.format(
            filePath, display_filter, jsonPath)
        proc = subprocess.Popen(command, shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate()
        return jsonPath

    def Split_HTTP_headers(self, file_data : bytes):
        # sourcery skip: use-named-expression
        headerEnd = file_data.find(b"\r\n\r\n")
        if headerEnd != -1:
            headerEnd += 4
            return file_data[:headerEnd], file_data[headerEnd:]
        elif file_data.find(b"\n\n") != -1:
            headerEnd = file_data.index(b"\n\n") + 2
            return file_data[:headerEnd], file_data[headerEnd:]
        else:
            print("[Warning] 没有找到headers和response的划分位置!")
            return b"", file_data

    def Dechunck_HTTP_response(self, file_data):
        """解码分块TCP数据

        Parameters
        ----------
        file_data : bytes
            已经切割掉headers的TCP数据

        Returns
        -------
        bytes
            解码分块后的TCP数据
        """
        chunks = []
        chunkSizeEnd = file_data.find(b"\n") + 1
        lineEndings = b'\r\n' if bytes([file_data[chunkSizeEnd-2]]) == b'\r' else b'\n'
        lineEndingsLength = len(lineEndings)
        while chunkSize := int(file_data[:chunkSizeEnd], 16):
            chunks.append(file_data[chunkSizeEnd:chunkSize + chunkSizeEnd])
            file_data = file_data[chunkSizeEnd + chunkSize + lineEndingsLength:]
            chunkSizeEnd = file_data.find(lineEndings) + lineEndingsLength
        return b''.join(chunks)

    def extract_http_file_data(self, full_request):
        # sourcery skip: merge-else-if-into-elif, swap-if-else-branches
        """提取HTTP请求或响应中的文件数据
        
        Parameters
        ----------
        full_request : bytes
            HTTP请求或响应的原始字节流
            
        Returns
        -------
        tuple
            包含header和file_data的元组
        """
        full_request = bytes.fromhex(full_request)
        header, file_data = self.Split_HTTP_headers(full_request)

        with contextlib.suppress(Exception):
            file_data = self.Dechunck_HTTP_response(file_data)
        
        with contextlib.suppress(Exception):
            if file_data.startswith(b"\x1F\x8B"):
                file_data = gzip.decompress(file_data)
        return header, file_data