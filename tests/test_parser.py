import binascii
import gzip
import unittest

from FlowAnalyzer.PacketParser import PacketParser


class TestPacketParserOptimization(unittest.TestCase):
    def test_gzip_decompression(self):
        # Construct a fake HTTP response with GZIP body
        content = b"Hello, Gzip World!"
        compressed = gzip.compress(content)
        header = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n"
        full_response = header + compressed

        full_request_hex = binascii.hexlify(full_response)

        # Test extract_http_file_data
        extracted_header, extracted_body = PacketParser.extract_http_file_data(full_request_hex)

        self.assertEqual(extracted_header, header)
        self.assertEqual(extracted_body, content)

    def test_basic_extraction(self):
        # Case: Simple text body, no chunking
        content = b"Simple Body"
        header = b"HTTP/1.1 200 OK\r\n\r\n"
        full_response = header + content
        full_request_hex = binascii.hexlify(full_response)

        extracted_header, extracted_body = PacketParser.extract_http_file_data(full_request_hex)
        self.assertEqual(extracted_body, content)

    def test_chunked_decoding(self):
        # Case: Chunked body
        # 5\r\nHello\r\n0\r\n\r\n
        chunked_body = b"5\r\nHello\r\n0\r\n\r\n"
        header = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        full_response = header + chunked_body
        full_request_hex = binascii.hexlify(full_response)

        extracted_header, extracted_body = PacketParser.extract_http_file_data(full_request_hex)
        self.assertEqual(extracted_body, b"Hello")


if __name__ == "__main__":
    unittest.main()
