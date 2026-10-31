"""D-3：关闭 fd 时的 OSError 不得覆盖正在传播的原始异常。

故障注入严格限定目标 fd：只对本次调用中实际打开的 fd 生效，
并且先真正 close 再抛错，避免测试自身泄漏 fd。
每个用例都断言注入确实触发（state["raised"]），防止空断言式通过。
"""

import errno
import io
import os
import stat
import unittest
from contextlib import redirect_stdout
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class ClosePreservesExceptionTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")

    # ------------------------------------------------------------------
    # 故障注入工具
    # ------------------------------------------------------------------

    def _capture_fds_from(self, attribute):
        """包装 main.<attribute>，记录它返回的 fd（按调用顺序）。"""
        real = getattr(main, attribute)
        captured = []

        def wrapper(*args, **kwargs):
            value = real(*args, **kwargs)
            captured.append(value)
            return value

        return wrapper, captured

    def _close_fault(self, predicate, message="close failed"):
        """只在 predicate(fd) 为真时：先真实 close，再抛 OSError。"""
        real_close = os.close
        state = {"raised": False}

        def failing(fd):
            real_close(fd)
            if predicate(fd):
                state["raised"] = True
                raise OSError(errno.EIO, message)

        return failing, state

    def _set_mode_or_skip(self, path, mode):
        os.chmod(path, mode)
        if stat.S_IMODE(os.stat(path).st_mode) != mode:
            self.skipTest("当前文件系统不支持设置该特殊权限位")

    def _sparse(self, name, size):
        path = self.project / name
        with open(path, "wb") as handle:
            handle.truncate(size)
        return path

    def assertNoSideEffects(self):
        self.assertEqual(self.backups(self.project), [], "不得产生正式 .bak")
        self.assertEqual(self.partials(self.project), [], "不得产生 .partial")

    # ------------------------------------------------------------------
    # 1) setgid 拒绝：关闭 source_fd 失败不得覆盖 PermissionError
    # ------------------------------------------------------------------

    def test_setgid_rejection_survives_source_fd_close_failure(self):
        target = self.make_file(self.project, "sgid.bin", b"hello\n")
        self._set_mode_or_skip(target, 0o2755)

        wrapper, captured = self._capture_fds_from("_open_target_no_follow")
        fault, state = self._close_fault(lambda fd: fd in captured)

        with mock.patch.object(
            main, "_open_target_no_follow", side_effect=wrapper
        ), mock.patch.object(main.os, "close", side_effect=fault):
            with self.assertRaises(PermissionError) as ctx:
                main.modify_file("proj", "sgid.bin", "hello", "HELLO")

        self.assertTrue(state["raised"], "关闭故障注入未触发")
        self.assertIn("setgid", str(ctx.exception), "必须保留 setgid 拒绝原因")
        self.assertNotIn("close failed", str(ctx.exception), "不得被 close 错误覆盖")
        self.assertEqual(target.read_bytes(), b"hello\n")
        self.assertNoSideEffects()

    # ------------------------------------------------------------------
    # 2) 超限拒绝：关闭 source_fd 失败不得覆盖 ValueError
    # ------------------------------------------------------------------

    def test_oversize_rejection_survives_source_fd_close_failure(self):
        size = main.MAX_MODIFY_FILE_BYTES + 1
        target = self._sparse("huge.txt", size)

        wrapper, captured = self._capture_fds_from("_open_target_no_follow")
        fault, state = self._close_fault(lambda fd: fd in captured)

        with mock.patch.object(
            main, "_open_target_no_follow", side_effect=wrapper
        ), mock.patch.object(main.os, "close", side_effect=fault):
            with self.assertRaises(ValueError) as ctx:
                main.modify_file("proj", "huge.txt", "A", "B")

        self.assertTrue(state["raised"], "关闭故障注入未触发")
        self.assertIn("超过修改上限", str(ctx.exception))
        self.assertNotIn("close failed", str(ctx.exception))
        self.assertEqual(target.stat().st_size, size)
        self.assertNoSideEffects()

    # ------------------------------------------------------------------
    # 3) 复核读取失败：关闭 check_fd 失败不得覆盖读取错误
    # ------------------------------------------------------------------

    def test_recheck_read_error_survives_check_fd_close_failure(self):
        target = self.make_file(self.project, "a.txt", b"hello\n")

        wrapper, captured = self._capture_fds_from("_open_target_no_follow")
        real_read = main._read_bounded
        calls = {"n": 0}

        def flaky_read(fd, limit):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_read(fd, limit)
            raise OSError(errno.EIO, "read failed")

        # 只让第二个 fd（check_fd）的关闭失败；source_fd 的关闭保持正常。
        fault, state = self._close_fault(
            lambda fd: len(captured) >= 2 and fd == captured[1]
        )

        with mock.patch.object(
            main, "_open_target_no_follow", side_effect=wrapper
        ), mock.patch.object(
            main, "_read_bounded", side_effect=flaky_read
        ), mock.patch.object(
            main.os, "close", side_effect=fault
        ), redirect_stdout(io.StringIO()):
            with self.assertRaises(OSError) as ctx:
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertTrue(state["raised"], "关闭故障注入未触发")
        self.assertIn("read failed", str(ctx.exception), "必须保留读取错误")
        self.assertNotIn("close failed", str(ctx.exception))
        self.assertEqual(target.read_bytes(), b"hello\n", "目标不得被修改")
        self.assertEqual(len(self.backups(self.project)), 1, "备份已发布，不得删除")
        self.assertEqual(self.partials(self.project), [])

    # ------------------------------------------------------------------
    # 4) 审计校验失败：关闭审计 fd 失败不得覆盖校验错误
    # ------------------------------------------------------------------

    def test_audit_validation_error_survives_close_failure(self):
        main.AUDIT_FILE.write_bytes(b"")
        os.chmod(main.AUDIT_FILE, 0o644)

        captured = []
        real_open = os.open

        def spy_open(path, flags, *args, **kwargs):
            fd = real_open(path, flags, *args, **kwargs)
            captured.append(fd)
            return fd

        fault, state = self._close_fault(lambda fd: fd in captured)

        with mock.patch.object(
            main.os, "open", side_effect=spy_open
        ), mock.patch.object(main.os, "close", side_effect=fault):
            with self.assertRaises(OSError) as ctx:
                main.audit_event("tool_succeeded", status="success")

        self.assertTrue(state["raised"], "关闭故障注入未触发")
        self.assertIn("权限必须为 600", str(ctx.exception))
        self.assertNotIn("close failed", str(ctx.exception))

    # ------------------------------------------------------------------
    # 5) 正常路径：关闭失败必须继续向调用方暴露
    # ------------------------------------------------------------------

    def test_normal_path_close_failure_still_propagates(self):
        target = self.make_file(self.project, "a.txt", b"hello\n")

        wrapper, captured = self._capture_fds_from("_open_target_no_follow")
        fault, state = self._close_fault(lambda fd: fd in captured)

        with mock.patch.object(
            main, "_open_target_no_follow", side_effect=wrapper
        ), mock.patch.object(main.os, "close", side_effect=fault):
            with self.assertRaises(OSError) as ctx:
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertTrue(state["raised"], "关闭故障注入未触发")
        self.assertIn("close failed", str(ctx.exception))
        self.assertEqual(target.read_bytes(), b"hello\n", "目标不得被修改")
        self.assertNoSideEffects()


if __name__ == "__main__":
    unittest.main()
