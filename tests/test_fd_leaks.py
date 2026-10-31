"""T-4：异常路径不得泄漏文件描述符。

计数方式：枚举 /proc/self/fd。os.scandir 自身会占用一个 fd，并在扫描
期间出现在列表里，因此减 1 得到"业务 fd"数量。计数在前后使用同一方法，
且先验证计数器稳定，不稳定则跳过，绝不编造通过结果。
"""

import errno
import io
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

import main
from tests.support import ChengxiangTestBase

FD_DIR = "/proc/self/fd"


def open_fd_count():
    """当前进程打开的 fd 数量（不含扫描目录自身那一个）。"""
    with os.scandir(FD_DIR) as entries:
        names = [entry.name for entry in entries]
    return len(names) - 1


class FdLeakTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")
        self.target = self.make_file(self.project, "a.txt", b"hello\n")

    def assertNoFdLeak(self, trigger, expected_exception):
        first = open_fd_count()
        second = open_fd_count()
        if first != second:
            self.skipTest(
                f"fd 计数不稳定（{first} vs {second}），无法可靠判断泄漏"
            )

        before = open_fd_count()
        with redirect_stdout(io.StringIO()):
            with self.assertRaises(expected_exception):
                trigger()
        after = open_fd_count()

        self.assertEqual(
            after, before,
            f"异常路径泄漏了 fd：异常前 {before}，异常后 {after}",
        )

    def test_counter_detects_a_real_leak(self):
        """对照组：证明 fd 计数器确实能发现泄漏，避免"空断言"式通过。"""
        before = open_fd_count()
        leaked = os.open(os.devnull, os.O_RDONLY)
        try:
            self.assertEqual(
                open_fd_count(), before + 1,
                "打开一个 fd 后计数应 +1",
            )
        finally:
            os.close(leaked)

        self.assertEqual(open_fd_count(), before, "关闭后计数应复原")

    # ------------------------------------------------------------------
    # 读取异常路径（C1）
    # ------------------------------------------------------------------

    def test_no_fd_leak_when_bounded_read_fails(self):
        def trigger():
            with mock.patch.object(
                main, "_read_bounded",
                side_effect=OSError(errno.EIO, "io error"),
            ):
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertNoFdLeak(trigger, OSError)

    # ------------------------------------------------------------------
    # 备份发布异常路径（C3）
    # ------------------------------------------------------------------

    def test_no_fd_leak_when_publish_fails(self):
        def trigger():
            with mock.patch.object(
                main, "_publish_backup",
                side_effect=main.BackupPublishError("发布被拒绝"),
            ):
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertNoFdLeak(trigger, main.BackupPublishError)

    # ------------------------------------------------------------------
    # 半成品写入异常路径（句柄必须被关闭）
    # ------------------------------------------------------------------

    def test_no_fd_leak_when_partial_write_fails(self):
        def trigger():
            with mock.patch.object(
                main.os, "fchmod",
                side_effect=OSError(errno.EIO, "io error"),
            ):
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertNoFdLeak(trigger, OSError)


if __name__ == "__main__":
    unittest.main()
