
import os
import shutil
import subprocess

from FlowAnalyzer.PcapSplitter import PcapSplitter

#############################
# 配置区
#############################
PCAP_FILE = r"./tests/Beyond_Pro.pcapng"  # 修改为你的文件
OUT_DIR = "output"
#############################

def clean_output_dir(directory: str):
    if os.path.exists(directory):
        print(f"Cleaning output directory: {directory}")
        shutil.rmtree(directory)
    os.makedirs(directory, exist_ok=True)

def count_packets(pcap_path: str, display_filter: str) -> int:
    cmd = [
        "tshark", 
        "-r", pcap_path, 
        "-Y", display_filter, 
        "-T", "fields", 
        "-e", "frame.number"
    ]
    try:
        # Run tshark and capture output
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=True
        )
        # Count non-empty lines
        count = sum(1 for line in result.stdout.splitlines() if line.strip())
        return count
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark on {pcap_path}: {e}")
        return 0
    except FileNotFoundError:
        print("Error: tshark not found in PATH.")
        return 0

def main():
    print("Beginning split test...")
    
    # 1. Clean output directory
    clean_output_dir(OUT_DIR)
    
    splitter = PcapSplitter(PCAP_FILE, OUT_DIR)
    
    # Defaults to os.cpu_count() chunks
    result_files = splitter.split()
    
    print(f"\nGenerated {len(result_files)} files:")
    for f in result_files:
        print(f)
        
    # 2. Verify with Tshark
    print("\nVerifying data integrity with Tshark...")
    total_requests = 0
    total_responses = 0
    
    EXPECTED_REQUESTS = 12284
    EXPECTED_RESPONSES = 12281
    
    for pcap in result_files:
        req_count = count_packets(pcap, "http.request")
        resp_count = count_packets(pcap, "http.response")
        
        print(f"  {os.path.basename(pcap)}: Requests={req_count}, Responses={resp_count}")
        total_requests += req_count
        total_responses += resp_count
        
    print("-" * 40)
    print(f"Total Requests: {total_requests} (Expected: {EXPECTED_REQUESTS})")
    print(f"Total Responses: {total_responses} (Expected: {EXPECTED_RESPONSES})")
    
    if total_requests == EXPECTED_REQUESTS and total_responses == EXPECTED_RESPONSES:
        print("\nSUCCESS: Data integrity verified.")
    else:
        print("\nFAILURE: Data integrity mismatch!")
        exit(1)


if __name__ == "__main__":
    main()
