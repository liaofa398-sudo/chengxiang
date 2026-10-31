"""F7：大文件读取的有界性。

重点：范围内单行按 max_bytes 预算早拒；内存上界与文件大小无关。
"""

import tracemalloc
import unittest
from pathlib import Path
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class _Recorder:
    """记录每次 read 的请求尺寸与实际返回长度。"""

    def __init__(self, handle, sizes):
        self._handle = handle
        self._sizes = sizes

    def read(self, n=-1):
        data = self._handle.read(n)
        self._sizes.append((n, len(data)))
        return data

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._handle.close()
        return False


class ReadLimitTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        main.AUTHORIZED_PERMISSION = "read"

    def _sparse(self, name, size):
        path = self.project / name
        with open(path, "wb") as handle:
            handle.truncate(size)
        return path

    def measure(self, func):
        tracemalloc.start()
        try:
            error = None
            try:
                func()
            except Exception as exc:  # noqa: BLE001 - 测试需要捕获任意异常
                error = exc
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        return error, peak

    def test_whole_read_over_hard_cap_rejected_before_reading(self):
        self._sparse("huge.txt", 9 * 1024 * 1024)
        with mock.patch.object(
            Path, "read_text", side_effect=AssertionError("不应读取")
        ):
            with self.assertRaises(ValueError) as ctx:
                main.read_file("proj", "huge.txt")
        self.assertIn("上限", str(ctx.exception))

    def test_whole_read_over_max_bytes_rejected_before_reading(self):
        self._sparse("big.txt", 40 * 1024)
        with mock.patch.object(
            Path, "read_text", side_effect=AssertionError("不应读取")
        ):
            with self.assertRaises(ValueError) as ctx:
                main.read_file("proj", "big.txt")
        self.assertIn("30000", str(ctx.exception))

    def test_in_range_40kb_line_rejected_far_below_1mib(self):
        self.make_file(self.project, "long.txt", b"x" * 40960)
        sizes = []
        real_open = Path.open

        def wrapper(target_self, *args, **kwargs):
            return _Recorder(real_open(target_self, *args, **kwargs), sizes)

        with mock.patch.object(Path, "open", new=wrapper):
            error, peak = self.measure(
                lambda: main.read_file(
                    "proj", "long.txt", start_line=1, end_line=1
                )
            )

        self.assertIsInstance(error, ValueError)
        self.assertIn("预算不足", str(error))

        total = sum(length for _, length in sizes)
        self.assertLessEqual(
            total,
            30000 + main.READ_CHUNK_BYTES,
            f"累计读取 {total} bytes 超出预算",
        )
        self.assertLess(total, 512 * 1024, "不应接近 1 MiB")
        self.assertLess(peak, 512 * 1024, f"内存峰值 {peak} 过高")

    def test_huge_in_range_line_reads_only_one_chunk(self):
        self.make_file(self.project, "huge_line.txt", b"y" * (5 * 1024 * 1024))
        sizes = []
        real_open = Path.open

        def wrapper(target_self, *args, **kwargs):
            return _Recorder(real_open(target_self, *args, **kwargs), sizes)

        with mock.patch.object(Path, "open", new=wrapper):
            with self.assertRaises(ValueError):
                main.read_file(
                    "proj", "huge_line.txt", start_line=1, end_line=1
                )

        total = sum(length for _, length in sizes)
        self.assertLessEqual(total, main.READ_CHUNK_BYTES)

    def test_read_chunk_size_is_constant(self):
        self.make_file(
            self.project, "multi.txt", b"".join(b"line\n" for _ in range(50))
        )
        sizes = []
        real_open = Path.open

        def wrapper(target_self, *args, **kwargs):
            return _Recorder(real_open(target_self, *args, **kwargs), sizes)

        with mock.patch.object(Path, "open", new=wrapper):
            main.read_file("proj", "multi.txt", start_line=1, end_line=5)

        self.assertTrue(sizes)
        for requested, _ in sizes:
            self.assertEqual(requested, main.READ_CHUNK_BYTES)

    def test_out_of_range_long_line_is_not_buffered(self):
        payload = b"z" * (2 * 1024 * 1024) + b"\ntarget\n"
        self.make_file(self.project, "skip.txt", payload)

        error, peak = self.measure(
            lambda: main.read_file(
                "proj", "skip.txt", start_line=2, end_line=2
            )
        )

        self.assertIsNone(error)
        self.assertLess(peak, 512 * 1024, f"内存峰值 {peak} 过高")

    def test_many_short_lines_are_bounded(self):
        payload = b"a\n" * 200_000
        self.make_file(self.project, "many.txt", payload)

        box = {}

        def run():
            box["result"] = main.read_file(
                "proj", "many.txt", start_line=1, end_line=500
            )

        error, peak = self.measure(run)

        self.assertIsNone(error)
        self.assertEqual(box["result"]["total_lines"], 200_000)
        self.assertEqual(box["result"]["content"].count("\n"), 499)
        self.assertLessEqual(box["result"]["bytes"], 30000)
        self.assertLess(peak, 512 * 1024, f"内存峰值 {peak} 过高")

    def test_scan_line_limit(self):
        self.make_file(self.project, "lines.txt", b"a\n" * 50)
        with mock.patch.object(main, "MAX_SCAN_LINES", 10):
            with self.assertRaises(ValueError) as ctx:
                main.read_file("proj", "lines.txt", start_line=1, end_line=2)
        self.assertIn("扫描行数", str(ctx.exception))

    def test_scan_byte_limit(self):
        self.make_file(
            self.project, "bytes.txt", b"abcdefgh\n" * 200
        )
        with mock.patch.object(main, "MAX_SCAN_BYTES", 1024):
            with self.assertRaises(ValueError) as ctx:
                main.read_file("proj", "bytes.txt", start_line=1, end_line=2)
        self.assertIn("扫描字节数", str(ctx.exception))

    def test_range_read_never_calls_read_text(self):
        self.make_file(self.project, "r.txt", b"a\nb\nc\n")
        with mock.patch.object(
            Path, "read_text", side_effect=AssertionError("不应读取")
        ):
            result = main.read_file("proj", "r.txt", start_line=1, end_line=2)
        self.assertEqual(result["content"], "a\nb")

    def test_crlf_is_stripped(self):
        self.make_file(self.project, "crlf.txt", b"a\r\nb\r\n")
        result = main.read_file("proj", "crlf.txt", start_line=1, end_line=2)
        self.assertEqual(result["content"], "a\nb")

    def test_no_trailing_newline_counts_last_line(self):
        self.make_file(self.project, "tail.txt", b"a\nb")
        result = main.read_file("proj", "tail.txt", start_line=1, end_line=5)
        self.assertEqual(result["total_lines"], 2)
        self.assertEqual(result["content"], "a\nb")

    def test_empty_file_start_line_out_of_range(self):
        self.make_file(self.project, "empty.txt", b"")
        with self.assertRaises(ValueError) as ctx:
            main.read_file("proj", "empty.txt", start_line=1, end_line=5)
        self.assertIn("超出文件范围", str(ctx.exception))

    def test_too_many_lines_requested(self):
        self.make_file(self.project, "x.txt", b"a\n" * 600)
        with self.assertRaises(ValueError):
            main.read_file("proj", "x.txt", start_line=1, end_line=600)


if __name__ == "__main__":
    unittest.main()
