import os
import time
from collections import defaultdict
from typing import List, Tuple

import dpkt


class PcapSplitter:
    """
    Encapsulates logic to split a PCAP/PCAPNG file into multiple smaller PCAP files
    based on TCP flows, dynamically balanced for parallel processing.
    """

    def __init__(self, pcap_file: str, output_dir: str):
        self.pcap_file = pcap_file
        self.output_dir = output_dir

    def get_stream_key(self, tcp, ip) -> Tuple:
        """Generate a 5-tuple key for the flow."""
        src = ip.src
        dst = ip.dst
        sport = tcp.sport
        dport = tcp.dport
        # Canonicalize bidirectional flows to the same key
        key1 = (src, dst, sport, dport)
        key2 = (dst, src, dport, sport)
        return key1 if key1 < key2 else key2

    def split(self, threshold_mb: int = 10, default_chunks: int = 3) -> List[str]:
        """
        Split the pcap file into balanced chunks based on stream volume (bytes).
        Uses a Greedy Partition Algorithm (Longest Processing Time first).

        Args:
            threshold_mb: File size threshold in MB. If smaller, do not split.
            default_chunks: Number of chunks to split into if threshold is exceeded.

        Returns:
            List of generated file paths (or original file if not split).
        """
        if not os.path.exists(self.pcap_file):
            raise FileNotFoundError(f"PCAP file not found: {self.pcap_file}")

        file_size_mb = os.path.getsize(self.pcap_file) / (1024 * 1024)
        if file_size_mb < threshold_mb:
            print(f"File size {file_size_mb:.2f}MB < {threshold_mb}MB. Skipping split.")
            return [self.pcap_file]

        os.makedirs(self.output_dir, exist_ok=True)

        start_time = time.time()
        # Dictionary to store packets: stream_key -> list of (ts, buf)
        streams = defaultdict(list)
        # Dictionary to store total size: stream_key -> total_bytes
        stream_sizes = defaultdict(int)

        # 1. Read and Group Packets
        print(f"Reading {self.pcap_file}...")
        with open(self.pcap_file, "rb") as f:
            if self.pcap_file.lower().endswith(".pcapng"):
                reader = dpkt.pcapng.Reader(f)
            else:
                reader = dpkt.pcap.Reader(f)

            for ts, buf in reader:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    if not isinstance(ip.data, dpkt.tcp.TCP):
                        continue
                    tcp = ip.data

                    key = self.get_stream_key(tcp, ip)
                    streams[key].append((ts, buf))
                    stream_sizes[key] += len(buf)
                except Exception:
                    continue

        total_streams = len(streams)
        print(f"Found {total_streams} TCP streams.")

        if total_streams == 0:
            print("No TCP streams found to split.")
            return []

        # 2. Assign Streams to Buckets (Greedy LPT Algorithm)
        num_chunks = min(default_chunks, total_streams)

        # Sort streams by size (descending)
        sorted_streams = sorted(stream_sizes.items(), key=lambda item: item[1], reverse=True)

        # Buckets: list of (current_size, batch_index, list_of_keys)
        # We perform standard list sort to find min bucket, sufficient for small N
        buckets = [[0, i, []] for i in range(num_chunks)]

        for key, size in sorted_streams:
            # Find bucket with smallest current size
            buckets.sort(key=lambda x: x[0])
            smallest_bucket = buckets[0]

            # Add stream to this bucket
            smallest_bucket[0] += size
            smallest_bucket[2].append(key)

        print(f"Splitting into {num_chunks} files with volume balancing...")
        generated_files = []

        # 3. Write Batches
        # Sort buckets by index ensures file naming order 0, 1, 2...
        buckets.sort(key=lambda x: x[1])

        for size, i, batch_keys in buckets:
            out_file_path = os.path.join(self.output_dir, f"batch_{i}.pcap")
            generated_files.append(out_file_path)

            with open(out_file_path, "wb") as f:
                writer = dpkt.pcap.Writer(f)
                for key in batch_keys:
                    for ts, buf in streams[key]:
                        writer.writepkt(buf, ts)

            print(f"  - Created {os.path.basename(out_file_path)}: {len(batch_keys)} streams ({size/1024/1024:.2f} MB)")

        print(f"Split completed in {time.time() - start_time:.2f}s")
        return generated_files