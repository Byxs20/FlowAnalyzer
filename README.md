# FlowAnalyzer

# 安装

使用 `pip` 安装：

```
pip3 install FlowAnalyzer
```

```
pip3 install FlowAnalyzer -i https://pypi.org/simple
```

# 快速上手

## 配置

如果您安装 `WireShark` 没有修改安装目录，默认 `tshark` 路径会如下：

```python
# windows
tshark_path = r"C:\Program Files\Wireshark\tshark.exe"
```

`Linux`, `MacOS` 默认路径不清楚，需要看下面的**纠正路径**，**确定路径没有问题，那也无需任何配置即可使用！**

## 纠正路径

修改 `python安装目录\Lib\site-packages\FlowAnalyzer\Path.py` 中的变量 `tshark_path` 改为**tshark正确路径**

## 测试

```
$ git clone https://github.com/Byxs20/FlowAnalyzer.git
$ cd ./FlowAnalyzer/
$ python -m tests.demo
```

运行结果：

```
[+] 正在处理第1个HTTP流!
序号: 2请求包, 请求头: b'POST /upload/php_eval_xor_base64.php HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0\r\n
...
```

# Contributing
Feel free to submit issues or pull requests if you have any suggestions, improvements, or bug reports.

# License

This project is licensed under the [MIT License.](LICENSE)
