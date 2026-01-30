# FlowAnalyzer

[![PyPI version](https://img.shields.io/pypi/v/FlowAnalyzer.svg)](https://pypi.org/project/FlowAnalyzer/) [![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) ![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)

**FlowAnalyzer** 是一个高效的 Python 流量分析库，基于 `Tshark` 进行底层解析。它专为处理大流量包（Large PCAP）设计，采用流式解析与 SQLite 缓存架构，彻底解决内存溢出问题，实现秒级二次加载。

---

## 🚀 核心特性：智能缓存与流式架构

为了解决传统解析方式慢、内存占用高的问题，FlowAnalyzer 进行了核心架构升级：**流式解析 + SQLite 智能缓存**。

### 1. ⚡️ 高性能流式解析
- **极低内存占用**：不再将整个 JSON 读入内存。通过 `subprocess` 管道对接 Tshark 输出，结合 `ijson` 进行增量解析。
- **无中间文件**：解析过程中不生成体积巨大的临时 JSON 文件，直接入库。

### 2. 💾 智能缓存机制
- **自动缓存**：首次分析 `test.pcap` 时，会自动生成同级目录下的 `test.db`。
- **秒级加载**：二次分析时，直接读取 SQLite 数据库，跳过漫长的 Tshark 解析过程（速度提升 100 倍+）。

### 3. 🛡️ 智能校验 (Smart Validation)
为了防止“修改了过滤规则但误读旧缓存”的问题，内置了严格的元数据校验机制。每次运行时自动比对指纹：

| 校验项                  | 说明                                                         |
| :---------------------- | :----------------------------------------------------------- |
| **过滤规则 (Filter)**   | 检查本次传入的 Tshark 过滤器（如 `http contains flag`）是否与缓存一致。 |
| **文件指纹 (Metadata)** | 检查原始 PCAP 文件的 **修改时间 (MTime)** 和 **文件大小 (Size)**。 |

- ✅ **命中缓存**：规则一致且文件未变 → **0秒等待，直接加载**。
- 🔄 **缓存失效**：规则变更或文件更新 → **自动重新解析并更新数据库**。

### 4. 性能对比

| 特性         | 旧版架构                      | **新版架构 (FlowAnalyzer)**         |
| :----------- | :---------------------------- | :---------------------------------- |
| **解析流程** | 生成巨大 JSON -> 全量读入内存 | Tshark流 -> 管道 -> ijson -> SQLite |
| **内存占用** | 极高 (易 OOM)                 | **极低 (内存稳定)**                 |
| **二次加载** | 需重新解析                    | **直接读取 DB (0秒)**               |
| **磁盘占用** | 巨大的临时 JSON 文件          | 轻量级 SQLite 文件                  |

---

## 📦 安装

请确保您的环境中已安装 Python 3 和 Tshark (Wireshark)。

```bash
# 安装 FlowAnalyzer 及其依赖 ijson
pip3 install FlowAnalyzer ijson

# 或者使用国内源加速
pip3 install FlowAnalyzer ijson -i https://pypi.org/simple
```

---

## 🛠️ 快速上手

### 1. 基础使用

```python
from FlowAnalyzer import FlowAnalyzer

# 流量包路径
pcap_path = r"tests/demo.pcap"
# 过滤规则
display_filter = "http"

# 1. 获取数据库数据 (自动处理解析、缓存和校验)
# 返回的是生成的 .db 文件路径
db_path = FlowAnalyzer.get_db_data(pcap_path, display_filter)
# 兼容老的函数名 get_json_data
# db_path = FlowAnalyzer.get_json_data(pcap_path, display_filter)

# 2. 初始化分析器
analyzer = FlowAnalyzer(db_path)

# 3. 遍历 HTTP 流
print("[+] 开始分析 HTTP 流...")
for pair in analyzer.generate_http_dict_pairs():
    if pair.request:
        print(f"Frame: {pair.request.frame_num} | URI: {pair.request.full_uri}")
        # 获取请求体数据
        # print(pair.request.file_data)
```

### 2. 配置 Tshark 路径

如果您的 `tshark` 不在系统环境变量中，程序可能会报错。您有两种方式进行配置：

**方法一：代码中指定 (推荐)**

在调用 `get_db_data` 时直接传入路径：

```python
tshark_ex = r"D:\Program Files\Wireshark\tshark.exe"

FlowAnalyzer.get_db_data(pcap_path, display_filter, tshark_path=tshark_ex)
```

**方法二：修改默认配置**

如果安装目录固定，可以修改库文件中的默认路径：
找到 `python安装目录\Lib\site-packages\FlowAnalyzer\Path.py`，修改 `tshark_path` 变量。

---

## 📝 测试

```bash
$ git clone https://github.com/Byxs20/FlowAnalyzer.git
$ cd ./FlowAnalyzer/
$ python tests/demo.py
```

**运行预期结果：**

```text
[+] 正在处理第1个HTTP流!
序号: 2请求包, 请求头: b'POST /upload/php_eval_xor_base64.php HTTP/1.1 ...
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).