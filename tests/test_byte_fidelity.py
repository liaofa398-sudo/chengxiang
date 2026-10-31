"""F4：字节级修改——严格 UTF-8、不做换行转换、备份为原始字节。"""

import unittest

import main
from tests.support import ChengxiangTestBase


class ByteFidelityTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")

    def test_non_utf8_file_is_rejected_without_change(self):
        original = "\u4e2d\u6587\u5185\u5bb9".encode("gbk")
        target = self.make_file(self.project, "gbk.txt", original)

        with self.assertRaises(ValueError) as ctx:
            main.modify_file("proj", "gbk.txt", "\u4e2d\u6587", "x")

        self.assertIn("非 UTF-8", str(ctx.exception))
        self.assertEqual(target.read_bytes(), original)
        self.assertEqual(self.backups(self.project), [])

    def test_invalid_bytes_are_rejected(self):
        original = b"\xff\xfehello"
        target = self.make_file(self.project, "bad.bin", original)
        with self.assertRaises(ValueError):
            main.modify_file("proj", "bad.bin", "hello", "HELLO")
        self.assertEqual(target.read_bytes(), original)

    def test_crlf_requires_exact_match(self):
        original = b"line1\r\nline2\r\n"
        target = self.make_file(self.project, "crlf.txt", original)

        with self.assertRaises(ValueError) as ctx:
            main.modify_file("proj", "crlf.txt", "line1\n", "LINE1\n")

        self.assertIn("未找到精确匹配", str(ctx.exception))
        self.assertEqual(target.read_bytes(), original)

    def test_crlf_preserved_everywhere_except_span(self):
        target = self.make_file(
            self.project, "crlf.txt", b"line1\r\nline2\r\nline3\r\n"
        )
        main.modify_file("proj", "crlf.txt", "line2\r\n", "LINE2\r\n")
        self.assertEqual(
            target.read_bytes(), b"line1\r\nLINE2\r\nline3\r\n"
        )

    def test_bom_is_preserved(self):
        target = self.make_file(
            self.project, "bom.txt", b"\xef\xbb\xbfhello\n"
        )
        main.modify_file("proj", "bom.txt", "hello", "HELLO")
        self.assertEqual(target.read_bytes(), b"\xef\xbb\xbfHELLO\n")

    def test_backup_is_byte_exact(self):
        original = "中文\r\n第二行\r\n".encode("utf-8")
        self.make_file(self.project, "b.txt", original)
        result = main.modify_file("proj", "b.txt", "第", "第X")
        with open(result["backup"], "rb") as handle:
            self.assertEqual(handle.read(), original)

    def test_only_target_span_changes(self):
        original = b"aaa\nbbb\nccc\n"
        target = self.make_file(self.project, "s.txt", original)
        main.modify_file("proj", "s.txt", "bbb", "B")
        self.assertEqual(target.read_bytes(), b"aaa\nB\nccc\n")

    def test_empty_file_matching(self):
        target = self.make_file(self.project, "e.txt", b"")
        with self.assertRaises(ValueError):
            main.modify_file("proj", "e.txt", "x", "y")
        self.assertEqual(target.read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
