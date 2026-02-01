import os

from FlowAnalyzer.FlowAnalyzer import FlowAnalyzer

# ============================
# 配置区域
# ============================
PCAP_FILE = "./tests/Beyond_Pro.pcapng"  # 你的测试 pcap 文件路径
DISPLAY_FILTER = "http"  # tshark display filter, 可以根据需求改


# ============================
# 测试逻辑
# ============================
def main():
    if not os.path.exists(PCAP_FILE):
        print(f"[ERROR] 流量包不存在: {PCAP_FILE}")
        return

    print("[*] 开始解析 PCAP 文件...")
    db_path = FlowAnalyzer.get_db_data(PCAP_FILE, DISPLAY_FILTER)
    print(f"[*] 解析完成，数据库生成: {db_path}")

    print("[*] 遍历 HTTP 请求-响应对:")
    analyzer = FlowAnalyzer(db_path)
    total = 0
    requests_count = 0
    responses_count = 0

    for pair in analyzer.generate_http_dict_pairs():
        total += 1
        if pair.request:
            requests_count += 1
        if pair.response:
            responses_count += 1

    print(f"[*] 总记录数: {total}")
    print(f"[*] 请求数量: {requests_count}")
    print(f"[*] 响应数量: {responses_count}")

    print("[*] 测试完成 ✅")


if __name__ == "__main__":
    main()
