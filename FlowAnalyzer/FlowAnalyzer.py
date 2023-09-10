import os
import re
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

    @staticmethod
    def extract_http_file_data(full_request):
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
        num = full_request.find(b"\r\n\r\n")
        header = full_request[:num]
        
        if full_request.endswith(b"\r\n\r\n[0-9a-f]{1,}\r\n"):
            # 判断是否有file_data，没有的话就为b""空字符串
            # 由于是多个tcp所以需要去除应该是长度的字节 不确定是不是4个字节 后期可能出现bug
            ret = re.findall(b'^\r\n\r\n[0-9a-f]{1,}\r\n(.*)\r\n\r\n$', full_request[num:], flags=re.DOTALL)
            file_data = re.sub(b"\r\n[0-9a-f]{1,}\r\n", b"", ret[0]) if ret != [] else b""
        else:
            file_data = full_request[num+4:]

        with contextlib.suppress(Exception):
            if b"\x1F\x8B".startswith(file_data):
                file_data = gzip.decompress(file_data)
        return header, file_data