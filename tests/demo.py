# sourcery skip: use-fstring-for-formatting
import os

from FlowAnalyzer import FlowAnalyzer

baseDir = os.path.dirname(os.path.abspath(__file__))
flowPath = os.path.join(baseDir, "flow.pcapng")
display_filter = "(http.request and urlencoded-form) or (http.request and data-text-lines) or (http.request and mime_multipart) or (http.response.code == 200 and data-text-lines)"

jsonPath = FlowAnalyzer.get_json_data(flowPath, display_filter=display_filter)
for http_seq_num, http in enumerate(FlowAnalyzer(jsonPath).generate_http_dict_pairs(), start=1):
    print(f"[+] 正在处理第{http_seq_num}个HTTP流!")
    
    request, response = http.request, http.response
    if request:
        request_num, header, file_data, time_epoch = request.frame_num, request.header, request.file_data, request.time_epoch
        print("序号: {}请求包, 请求头: {}, 文件: {}, 时间: {}".format(request_num, header, file_data, time_epoch))

    if response:
        response_num, header, file_data, time_epoch = response.frame_num, response.header, response.file_data, response.time_epoch
        print("序号: {}请求包, 请求头: {}, 文件: {}, 时间: {}".format(response_num, header, file_data, time_epoch))