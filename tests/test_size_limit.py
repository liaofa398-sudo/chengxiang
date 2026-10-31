"""C1：modify_file 的输入大小上限。

验证：超过上限被拒绝、拒绝时不产生备份、
文件在检查后增长也绕不过上限（读取确实有界）、正常文件不受影响。
"""

import hashlib
import io
import os
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class SizeLimitTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")

    def _sparse(self, name, size):
        path = self.project / name
        with open(path, "wb") as handle:
            handle.truncate(size)
        return path

    # ------------------------------------------------------------------
    # 超限拒绝
    # ------------------------------------------------------------------

    def test_oversized_file_is_rejected_and_bytes_unchanged(self):
        size = main.MAX_MODIFY_FILE_BYTES + 1
        target = self._sparse("huge.txt", size)
        before = hashlib.sha256(target.read_bytes()).hexdigest()

        with self.assertRaises(ValueError) as ctx:
            main.modify_file("proj", "huge.txt", "A", "B")

        self.assertIn("超过修改上限", str(ctx.exception))
        self.assertEqual(target.stat().st_size, size)
        self.assertEqual(
            hashlib.sha256(target.read_bytes()).hexdigest(), before
        )

    def test_oversized_rejection_creates_no_backup_at_all(self):
        size = main.MAX_MODIFY_FILE_BYTES + 1
        target = self._sparse("huge.txt", size)
        before = hashlib.sha256(target.read_bytes()).hexdigest()

        with self.assertRaises(ValueError):
            main.modify_file("proj", "huge.txt", "A", "B")

        # 直接枚举真实目录内容，不依赖 mock、缓存或返回值。
        names = sorted(p.name for p in self.project.iterdir())
        self.assertEqual(
            [n for n in names if n.endswith(".before_chengxiang_modify.bak")],
            [],
            f"不得产生正式 .bak，实际目录内容：{names}",
        )
        self.assertEqual(
            [n for n in names if n.endswith(".before_chengxiang_modify.partial")],
            [],
            f"不得产生 .partial，实际目录内容：{names}",
        )

        # 目标文件必须逐字节不变。
        self.assertEqual(
            hashlib.sha256(target.read_bytes()).hexdigest(),
            before,
            "目标文件内容必须保持不变",
        )
        self.assertEqual(target.stat().st_size, size)

    # ------------------------------------------------------------------
    # 检查之后发生增长：不能绕过上限
    # ------------------------------------------------------------------

    def test_growth_after_size_check_cannot_bypass_limit(self):
        """fstat 谎报小尺寸，实际文件超限；读取仍必须被截断并拒绝。"""
        size = main.MAX_MODIFY_FILE_BYTES + 1
        target = self._sparse("grow.txt", size)

        real_fstat = os.fstat
        real_read = os.read
        read_sizes = []

        def lying_fstat(fd):
            info = real_fstat(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_size=1)

        def counting_read(fd, count):
            data = real_read(fd, count)
            read_sizes.append(len(data))
            return data

        with mock.patch.object(main.os, "fstat", side_effect=lying_fstat), \
                mock.patch.object(main.os, "read", side_effect=counting_read):
            with self.assertRaises(ValueError) as ctx:
                main.modify_file("proj", "grow.txt", "A", "B")

        self.assertIn("超过修改上限", str(ctx.exception))
        self.assertLessEqual(
            sum(read_sizes), main.MAX_MODIFY_FILE_BYTES + 1,
            f"实际读取 {sum(read_sizes)} bytes，超出硬上限",
        )
        self.assertGreater(
            sum(read_sizes), main.MAX_MODIFY_FILE_BYTES,
            "应当读取到上限以识别超限文件",
        )
        self.assertEqual(target.stat().st_size, size)
        self.assertEqual(self.backups(self.project), [])

    # ------------------------------------------------------------------
    # 边界与正常路径
    # ------------------------------------------------------------------

    def test_exact_limit_is_accepted(self):
        with mock.patch.object(main, "MAX_MODIFY_FILE_BYTES", 32):
            target = self.make_file(
                self.project, "eq.txt", b"hello\n" + b"x" * 26
            )
            with redirect_stdout(io.StringIO()):
                main.modify_file("proj", "eq.txt", "hello", "HELLO")

        self.assertTrue(target.read_bytes().startswith(b"HELLO\n"))
        self.assertEqual(target.stat().st_size, 32)

    def test_one_byte_over_configured_limit_is_rejected(self):
        with mock.patch.object(main, "MAX_MODIFY_FILE_BYTES", 32):
            target = self.make_file(
                self.project, "over.txt", b"hello\n" + b"x" * 27
            )
            with self.assertRaises(ValueError):
                main.modify_file("proj", "over.txt", "hello", "HELLO")

        self.assertEqual(target.read_bytes(), b"hello\n" + b"x" * 27)
        self.assertEqual(self.backups(self.project), [])

    def test_normal_size_file_still_modifies(self):
        target = self.make_file(self.project, "ok.txt", b"hello\n")

        with redirect_stdout(io.StringIO()):
            result = main.modify_file("proj", "ok.txt", "hello", "HELLO")

        self.assertEqual(target.read_bytes(), b"HELLO\n")
        self.assertEqual(result["replaced"], 1)
        self.assertTrue(os.path.exists(result["backup"]))


if __name__ == "__main__":
    unittest.main()
