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

        request, response = {}, []
        for packet in data:
            packet = packet["_source"]["layers"]
            time_epoch = float(packet["frame.time_epoch"][0]) if packet.get("frame.time_epoch") else None
            full_request = packet["tcp.reassembled.data"][0] if packet.get("tcp.reassembled.data") else packet["tcp.payload"][0]
            response_num = int(packet["frame.number"][0]) if packet.get("frame.number") else None
            request_num = int(packet["http.request_in"][0]) if packet.get("http.request_in") else None
            
            if request_num:
                response.append({"response_num": response_num, "request_in": request_num, "full_request": full_request, "time_epoch": time_epoch})
            else:
                request[response_num] = {"full_request": full_request, "time_epoch": time_epoch}
        return request, response

    def generate_http_dict_pairs(self, preserve_http_headers=False, preserve_start_time=False):
        """生成HTTP请求和响应信息的字典对

        Parameters
        ----------
        preserve_http_headers : bool, optional
            指是否保留HTTP除了请求体/返回体以外的所有HTTP头部信息，默认为False，只会返回HTTP请求体或者返回体
            
            如下结构：
            请求行/返回行：
                请求行：指的是HTTP请求中的第一行，包含了HTTP方法、请求的资源路径和HTTP协议版本。例如：GET /index.html HTTP/1.1
                返回行：指的是HTTP响应中的第一行，包含了HTTP协议版本、响应状态码和相应的状态描述。例如：HTTP/1.1 200 OK
            请求头/返回头：
                请求头：包含了HTTP请求的相关信息，以键值对的形式出现，每个键值对占据一行。常见的请求头包括Host、User-Agent、Content-Type等。例如：Host: example.com
                返回头：包含了HTTP响应的相关信息，也是以键值对的形式出现，每个键值对占据一行。常见的返回头包括Content-Type、Content-Length、Server等。例如：Content-Type: text/html
            空行：用于分隔请求头和请求体，由两个连续的回车换行符组成
            请求体/返回体：
                请求体：包含了HTTP请求中的实际数据部分，通常在POST请求中使用。请求体可以是表单数据、JSON数据等，格式取决于请求头中的Content-Type字段
                返回体：包含了HTTP响应中的实际数据部分，通常是服务器返回给客户端的内容。返回体的格式和内容取决于具体的请求和服务器的处理逻辑
        
        preserve_start_time : bool, optional
            指是保留HTTP请求的时间，指的是开始时间

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
            
            dic = {"response": [frame_num, self.extract_http_file_data(resp['full_request'], preserve_http_headers)]}
            dic["request"] = [request_num, self.extract_http_file_data(requ["full_request"], preserve_http_headers)] if requ else None

            if preserve_start_time:
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
    def extract_http_file_data(full_request, preserve_http_headers=False):
        # sourcery skip: merge-else-if-into-elif, swap-if-else-branches
        """提取HTTP请求或响应中的文件数据

        Parameters
        ----------
        full_request : str
            HTTP请求或响应的消息体
        preserve_http_headers : bool, optional
            指是否保留HTTP除了请求体/返回体以外的所有HTTP头部信息，默认为False，只会返回HTTP请求体或者返回体
            
            如下结构：
            请求行/返回行：
                请求行：指的是HTTP请求中的第一行，包含了HTTP方法、请求的资源路径和HTTP协议版本。例如：GET /index.html HTTP/1.1
                返回行：指的是HTTP响应中的第一行，包含了HTTP协议版本、响应状态码和相应的状态描述。例如：HTTP/1.1 200 OK
            请求头/返回头：
                请求头：包含了HTTP请求的相关信息，以键值对的形式出现，每个键值对占据一行。常见的请求头包括Host、User-Agent、Content-Type等。例如：Host: example.com
                返回头：包含了HTTP响应的相关信息，也是以键值对的形式出现，每个键值对占据一行。常见的返回头包括Content-Type、Content-Length、Server等。例如：Content-Type: text/html
            空行：用于分隔请求头和请求体，由两个连续的回车换行符组成
            请求体/返回体：
                请求体：包含了HTTP请求中的实际数据部分，通常在POST请求中使用。请求体可以是表单数据、JSON数据等，格式取决于请求头中的Content-Type字段
                返回体：包含了HTTP响应中的实际数据部分，通常是服务器返回给客户端的内容。返回体的格式和内容取决于具体的请求和服务器的处理逻辑

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
        return header + b"\r\n\r\n" + file_data if preserve_http_headers else file_data