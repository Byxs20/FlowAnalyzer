import os
import re
import json
import gzip
import subprocess
from typing import Tuple


class FlowAnalyzer:
    """FlowAnalyzer是一个流量分析器，用于解析和处理tshark导出的JSON数据文件"""
    
    def __init__(self, jsonPath : str):
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
            raise FileNotFoundError(f"您的tshark导出的JSON文件没有找到！JSON路径：%s" % self.jsonPath)
        
        if os.path.getsize(self.jsonPath) == 0:
            raise ValueError("您的tshark导出的JSON文件内容为空！JSON路径：%s" % self.jsonPath)

    def parse_http_json(self) -> Tuple[dict, list]:
        """解析JSON数据文件中的HTTP请求和响应信息

        Returns
        -------
        tuple
            包含请求字典和响应列表的元组
        """
        with open(self.jsonPath, "r") as f:
            data = json.load(f)
            
        request, response = {}, []
        for packet in data:
            packet = packet["_source"]["layers"]
            file_data = packet.get("tcp.reassembled.data") or packet["tcp.payload"]
            if packet.get("http.request_in"):
                response.append({"response_num": packet["frame.number"][0], "request_in": packet["http.request_in"][0], "http_body": file_data[0]})
            else:
                request[packet["frame.number"][0]] = file_data[0]
        return request, response
    
    def generate_http_dict_pairs(self, extract=True):
        """生成HTTP请求和响应信息的字典对

        Parameters
        ----------
        extract : bool, optional
            指示是否提取HTTP文件数据，默认为True，表示提取，否则返回原始数据

        Yields
        ------
        Iterator[dict]
            包含请求和响应信息的字典迭代器
        """
        request, response = self.parse_http_json()
        for resp in response:
            frame_num = resp["response_num"]
            request_num = resp["request_in"]
            http_body = request.get(request_num)
            yield {
                "response": [
                    frame_num,
                    self.extract_http_file_data(resp['http_body'])
                    if extract
                    else resp['http_body'],
                ],
                "request": [
                    request_num,
                    self.extract_http_file_data(http_body)
                    if http_body and extract
                    else http_body,
                ]
                if http_body
                else None,
            }

    @staticmethod
    def get_json_data(filePath, display_filter):
        """获取JSON数据并保存至文件

        Parameters
        ----------
        filePath : str
            待处理的数据文件路径
        display_filter : str
            Tshark的过滤器表达式

        Returns
        -------
        str
            保存JSON数据的文件路径
        """
        # sourcery skip: use-fstring-for-formatting
        # jsonPath = os.path.join(os.path.dirname(filePath), "output.json")
        jsonPath = os.path.join(os.getcwd(), "output.json")
        command = 'tshark -r {} -Y "{}" -T json -e http.request_in -e tcp.reassembled.data -e frame.number -e tcp.payload > {}'.format(filePath, display_filter, jsonPath)
        proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate()
        return jsonPath

    @staticmethod
    def extract_http_file_data(http_body):
        """提取HTTP请求或响应中的文件数据

        Parameters
        ----------
        http_body : str
            HTTP请求或响应的消息体

        Returns
        -------
        bytes
            解压缩后的文件数据
        """
        http_body = bytes.fromhex(http_body)
        if not http_body.endswith(b"\r\n\r\n"):
            num = http_body.find(b"\r\n\r\n")
            data = http_body[num+4:]
        else:
            num = http_body.find(b"\r\n\r\n")
            data = re.findall(b'^\r\n\r\n.*?\r\n(.*)\r\n.*?\r\n\r\n$', http_body[num:], flags=re.DOTALL)[0]
            data = re.sub(b"\r\n.{4}\r\n", b"", data) # 由于是多个tcp所以需要去除应该是长度的字节 不确定是不是4个字节 后期可能出现bug
        
        try:
            return gzip.decompress(data)
        except gzip.BadGzipFile:
            return data
        