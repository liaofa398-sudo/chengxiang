"""D-2：modify_file 打开目标文件时必须拒绝最终组件的符号链接。

覆盖：静态符号链接、lstat 之后被换成符号链接、备份发布之后被换成符号链接、
O_NOFOLLOW 是否真的传给了内核、平台不支持该标志时是否 fail-closed。

注意：O_NOFOLLOW 只保护**最终路径组件**；父目录组件中的符号链接由
"解析父目录 + target.relative_to(root)" 负责，不由本组测试断言。
"""

import errno
import io
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class NoFollowTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")
        self.target = self.make_file(self.project, "a.txt", b"hello\n")
        self.target_abs = str(self.target.resolve())

    def assertNoSideEffects(self):
        self.assertEqual(self.backups(self.project), [], "不得产生正式 .bak")
        self.assertEqual(self.partials(self.project), [], "不得产生 .partial")

    # ------------------------------------------------------------------
    # 1) 静态符号链接
    # ------------------------------------------------------------------

    def test_symlink_target_is_refused(self):
        victim = self.make_file(self.project, "victim.txt", b"victim-data")
        os.unlink(self.target)
        os.symlink(str(victim), self.target)

        with redirect_stdout(io.StringIO()):
            with self.assertRaises(PermissionError) as ctx:
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertIn("符号链接", str(ctx.exception))
        self.assertEqual(victim.read_bytes(), b"victim-data", "链接目标不得被修改")
        self.assertTrue(self.target.is_symlink(), "链接本身不得被删除")
        self.assertNoSideEffects()

    # ------------------------------------------------------------------
    # 2) O_NOFOLLOW 是否真的传给了内核
    # ------------------------------------------------------------------

    def test_open_uses_o_nofollow_flag(self):
        real_open = os.open
        calls = []

        def spy(path, flags, *args, **kwargs):
            calls.append((str(path), flags))
            return real_open(path, flags, *args, **kwargs)

        with mock.patch.object(main.os, "open", side_effect=spy), \
                redirect_stdout(io.StringIO()):
            main.modify_file("proj", "a.txt", "hello", "HELLO")

        target_flags = [
            flags for path, flags in calls if path == self.target_abs
        ]
        self.assertTrue(target_flags, "未观察到对目标文件的 open 调用")
        for flags in target_flags:
            self.assertTrue(
                flags & os.O_NOFOLLOW,
                f"目标文件的 open 未携带 O_NOFOLLOW：flags={flags:#o}",
            )

    # ------------------------------------------------------------------
    # 3) lstat 之后、open 之前被换成符号链接
    # ------------------------------------------------------------------

    def test_swapped_to_symlink_before_open_is_refused(self):
        victim = self.make_file(self.project, "victim.txt", b"victim-data")
        real_lstat = os.lstat
        state = {"swapped": False}

        def swap_after_lstat(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if not state["swapped"] and str(path) == self.target_abs:
                state["swapped"] = True
                os.unlink(self.target_abs)
                os.symlink(str(victim), self.target_abs)
            return info

        with mock.patch.object(
            main.os, "lstat", side_effect=swap_after_lstat
        ), redirect_stdout(io.StringIO()):
            with self.assertRaises(PermissionError) as ctx:
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertTrue(state["swapped"], "替换注入未生效")
        self.assertIn("符号链接", str(ctx.exception))
        self.assertEqual(victim.read_bytes(), b"victim-data", "链接目标不得被修改")
        self.assertNoSideEffects()

    # ------------------------------------------------------------------
    # 4) 普通目标文件仍可正常修改（C1/C3/D-1 行为不变）
    # ------------------------------------------------------------------

    def test_regular_target_still_modifies(self):
        with redirect_stdout(io.StringIO()):
            result = main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertEqual(self.target.read_bytes(), b"HELLO\n")
        self.assertTrue(os.path.exists(result["backup"]))
        self.assertEqual(self.partials(self.project), [])

    # ------------------------------------------------------------------
    # 5) 平台不支持该标志：明确拒绝，不静默降级
    # ------------------------------------------------------------------

    def test_missing_nofollow_flag_is_fail_closed(self):
        with mock.patch.object(main.os, "O_NOFOLLOW", None), \
                redirect_stdout(io.StringIO()):
            with self.assertRaises(PermissionError) as ctx:
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertIn("O_NOFOLLOW", str(ctx.exception))
        self.assertEqual(self.target.read_bytes(), b"hello\n")
        self.assertNoSideEffects()

    def test_emlink_is_not_reported_as_symlink_denial(self):
        """EMLINK 不属于符号链接拒绝，必须走通用的打开失败路径。"""
        real_open = main.os.open

        def emlink_for_target(path, *args, **kwargs):
            # 只对目标文件注入 EMLINK：锁文件打开必须正常进行。
            if str(path) == str(self.target):
                raise OSError(errno.EMLINK, "too many links")
            return real_open(path, *args, **kwargs)

        with mock.patch.object(
            main.os, "open", side_effect=emlink_for_target,
        ), redirect_stdout(io.StringIO()):
            with self.assertRaises(RuntimeError) as ctx:
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertNotIsInstance(ctx.exception, PermissionError)
        self.assertIn("阶段：open", str(ctx.exception))
        self.assertEqual(self.target.read_bytes(), b"hello\n")
        self.assertNoSideEffects()

    # ------------------------------------------------------------------
    # 6) 备份发布之后、替换前复核时被换成符号链接
    # ------------------------------------------------------------------

    def test_swapped_to_symlink_before_recheck_is_refused(self):
        victim = self.make_file(self.project, "victim.txt", b"victim-data")
        real_publish = main._publish_backup

        def publish_then_swap(partial, target_path):
            official = real_publish(partial, target_path)
            os.unlink(self.target_abs)
            os.symlink(str(victim), self.target_abs)
            return official

        with mock.patch.object(
            main, "_publish_backup", side_effect=publish_then_swap
        ), redirect_stdout(io.StringIO()):
            with self.assertRaises(PermissionError) as ctx:
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertIn("符号链接", str(ctx.exception))
        self.assertEqual(victim.read_bytes(), b"victim-data", "链接目标不得被修改")
        self.assertEqual(
            len(self.backups(self.project)), 1,
            "备份在替换前已发布，不得删除",
        )


if __name__ == "__main__":
    unittest.main()
