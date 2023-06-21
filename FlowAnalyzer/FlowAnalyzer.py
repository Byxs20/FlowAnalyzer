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
            time_epoch = packet.get("frame.time_epoch")
            full_request = packet.get(
                "tcp.reassembled.data") or packet["tcp.payload"]

            if packet.get("http.request_in"):
                response.append({"response_num": packet["frame.number"][0], "request_in": packet["http.request_in"]
                                [0], "full_request": full_request[0], "time_epoch": float(time_epoch[0])})
            else:
                request[packet["frame.number"][0]] = {
                    "full_request": full_request[0], "time_epoch": float(time_epoch[0])}
        return request, response

    def generate_http_dict_pairs(self, http_header=False, time_epoch=False):
        """生成HTTP请求和响应信息的字典对

        Parameters
        ----------
        http_header : bool, optional
            指是否提取HTTP请求的全部，默认为False，表示只提取请求体，否则返回整个HTTP请求，如下结构：
            请求行：请求方法、请求目标和 HTTP 协议版本组成，例如 POST /login.php HTTP/1.1。
            请求头：包含了各种请求的元数据，比如 Host、Content-Length、User-Agent 等。每个请求头都由一个字段名和对应的值组成，以冒号分隔，例如 Host: 192.168.52.176。
            空行：用于分隔请求头和请求体，由两个连续的回车换行符组成。
            请求体：包含了请求的实际数据，对于 POST 请求来说，请求体通常包含表单数据或其他数据，以便发送给服务器进行处理。
        time_epoch : bool, optional
            指是否提取HTTP请求的时间，指的是开始时间

        Yields
        ------
        Iterator[dict]
            包含请求和响应信息的字典迭代器
        """
        request, response = self.parse_http_json()
        for resp in response:
            frame_num = resp["response_num"]
            request_num = resp["request_in"]
            requ = request.get(request_num)
            
            dic = {"response": [frame_num, self.extract_http_file_data(resp['full_request'], http_header)]}
            dic["request"] = [request_num, self.extract_http_file_data(requ["full_request"], http_header)] if requ else None

            if time_epoch:
                dic["response"].append(resp["time_epoch"])
                dic["request"].append(requ["time_epoch"]) if requ else None
            yield dic

    @staticmethod
    def get_json_data(filePath, display_filter):
        """获取JSON数据并保存至文件，保存目录是当前工作目录，也就是您运行脚本所在目录

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
        command = 'tshark -r {} -Y "{}" -T json -e http.request_in -e tcp.reassembled.data -e frame.number -e tcp.payload -e frame.time_epoch > {}'.format(
            filePath, display_filter, jsonPath)
        proc = subprocess.Popen(command, shell=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        proc.communicate()
        return jsonPath

    @staticmethod
    def extract_http_file_data(full_request, http_header=False):
        # sourcery skip: merge-else-if-into-elif, swap-if-else-branches
        """提取HTTP请求或响应中的文件数据

        Parameters
        ----------
        full_request : str
            HTTP请求或响应的消息体
        http_header : bool, optional
            指是否提取HTTP请求的全部，默认为False，表示只提取请求体，否则返回整个HTTP请求，如下结构：
            请求行：请求方法、请求目标和 HTTP 协议版本组成，例如 POST /login.php HTTP/1.1。
            请求头：包含了各种请求的元数据，比如 Host、Content-Length、User-Agent 等。每个请求头都由一个字段名和对应的值组成，以冒号分隔，例如 Host: 192.168.52.176。
            空行：用于分隔请求头和请求体，由两个连续的回车换行符组成。
            请求体：包含了请求的实际数据，对于 POST 请求来说，请求体通常包含表单数据或其他数据，以便发送给服务器进行处理。

        Returns
        -------
        bytes
            HTTP的bytes类型，如果有Gzip数据会自动解压缩
        """
        full_request = bytes.fromhex(full_request)
        num = full_request.find(b"\r\n\r\n")
        header = full_request[:num]
        
        if full_request.endswith(b"\r\n\r\n"):
            ret = re.findall(b'^\r\n\r\n.*?\r\n(.*)\r\n.*?\r\n\r\n$', full_request[num:], flags=re.DOTALL)
            # 判断是否有file_data，没有的话就为b""空字符串
            # 由于是多个tcp所以需要去除应该是长度的字节 不确定是不是4个字节 后期可能出现bug
            file_data = re.sub(b"\r\n.{4}\r\n", b"", ret[0]) if ret != [] else b""
        else:
            file_data = full_request[num+4:]

        with contextlib.suppress(Exception):
            file_data = gzip.decompress(file_data)
        return header + b"\r\n\r\n" + file_data if http_header else file_data