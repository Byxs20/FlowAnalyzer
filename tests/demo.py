# sourcery skip: use-fstring-for-formatting
import os
from FlowAnalyzer import FlowAnalyzer


baseDir = os.path.dirname(os.path.abspath(__file__))
display_filter = display_filter = "(http.request and urlencoded-form) or (http.request and data-text-lines) or (http.request and mime_multipart) or (http.response.code == 200 and data-text-lines)"

jsonPath = FlowAnalyzer.get_json_data(os.path.join(baseDir, "flow.pcapng"), display_filter=display_filter)

for count, dic in enumerate(FlowAnalyzer(jsonPath).generate_http_dict_pairs(), start=1):
    print(f"[+] 正在处理第{count}个HTTP流!")
    response_num, file_data = dic['response']
    print("序号: {}返回包, 文件: {}".format(response_num, file_data))
    
    request = dic.get("request")
    if not request:
        continue
    
    request_num, file_data = request
    print("序号: {}请求包, 文件: {}".format(request_num, file_data))