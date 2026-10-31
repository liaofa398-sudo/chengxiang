"""D-4：临时文件 fd 的所有权与关闭语义。

方案 B：os.fdopen(..., closefd=False)，fd 始终由 modify_file 持有，
文件对象只负责 write / flush / fsync，绝不代劳关闭。

本组测试验证：
- 任何失败路径下临时 fd 都被关闭一次（且只有一次）；
- 有在飞异常时，关闭失败不覆盖原始异常；
- 正常路径的关闭失败照常向调用方传播；
- 文件对象的关闭状态与底层 fd 的关闭状态彼此分离。

测试纪律：
- 真实 os.close / os.fdopen 在任何 mock 之前保存，清理阶段只用它们；
- 故障注入只命中本次记录到的临时 fd，其余 fd 一律调用真实函数；
- 不使用 skipTest；不依赖 fd 编号被复用。
"""

import errno
import os
import unittest
from unittest import mock

import main
from tests.support import ChengxiangTestBase

# 在任何 mock 之前捕获真实实现，供测试清理阶段使用
_REAL_CLOSE = os.close
_REAL_FDOPEN = os.fdopen

# fd 关闭故障的专用消息：刻意不与 "file object close failed" 互为子串，
# 以便用 assertIn/assertNotIn 精确区分"哪条异常在传播"。
_FD_CLOSE_ERROR = "injected temp fd close"


def open_fd_count():
    """当前进程打开的 fd 数量（扣除 scandir 自身占用的一个）。"""
    with os.scandir("/proc/self/fd") as entries:
        return len([entry.name for entry in entries]) - 1


def _fd_is_open(fd):
    try:
        os.fstat(fd)
    except OSError:
        return False
    return True


class _FaultyFile:
    """包住真实文件对象，按需在 write / flush / 退出时抛错。

    __exit__ 只关闭文件对象；由于底层以 closefd=False 创建，
    关闭文件对象不会关闭底层 fd。
    """

    def __init__(self, inner, on_write=None, on_flush=None, on_exit=None):
        self._inner = inner
        self._on_write = on_write
        self._on_flush = on_flush
        self._on_exit = on_exit

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._inner.close()
        if self._on_exit:
            raise OSError(errno.EIO, self._on_exit)
        return False

    def write(self, data):
        if self._on_write:
            raise OSError(errno.EIO, self._on_write)
        return self._inner.write(data)

    def flush(self):
        if self._on_flush:
            raise OSError(errno.EIO, self._on_flush)
        return self._inner.flush()

    def __getattr__(self, name):
        return getattr(self._inner, name)


class TempFdOwnershipTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")
        self.target = self.make_file(self.project, "a.txt", b"hello\n")

        # 哨兵 fd：用于证明"没有误关其他 fd"
        self.sentinel = os.open(os.devnull, os.O_RDONLY)
        self.addCleanup(self._close_quietly, self.sentinel)

        # 基线在哨兵打开之后测量，因此包含哨兵
        self.baseline = open_fd_count()

    def _close_quietly(self, fd):
        """只用真实 close 清理，对 EBADF 幂等。"""
        try:
            _REAL_CLOSE(fd)
        except OSError:
            pass

    def assertBusinessStateUnchanged(self):
        self.assertEqual(self.target.read_bytes(), b"hello\n",
                         "目标文件必须保持原内容")
        self.assertEqual(
            [p.name for p in self.project.iterdir()
             if ".chengxiang_tmp_" in p.name],
            [],
            "临时文件必须按既有策略清理",
        )
        self.assertEqual(len(self.backups(self.project)), 1,
                         "正式备份在替换前已发布，必须保留")
        self.assertEqual(self.partials(self.project), [],
                         "正式发布后不得残留 .partial")
        self.assertTrue(_fd_is_open(self.sentinel), "哨兵 fd 被误关")

    # ------------------------------------------------------------------
    # 1) fdopen 构造失败
    # ------------------------------------------------------------------

    def test_fdopen_failure(self):
        captured = []

        def failing_fdopen(fd, *args, **kwargs):
            captured.append(fd)
            self.assertIs(kwargs.get("closefd"), False,
                          "必须以 closefd=False 创建文件对象")
            raise OSError(errno.EIO, "fdopen failed")

        try:
            with mock.patch.object(main.os, "fdopen",
                                   side_effect=failing_fdopen):
                with self.assertRaises(OSError) as ctx:
                    main.modify_file("proj", "a.txt", "hello", "HELLO")

            self.assertEqual(len(captured), 1, "未捕获到本次创建的临时 fd")
            self.assertIn("fdopen failed", str(ctx.exception))
            self.assertFalse(_fd_is_open(captured[0]),
                             "fdopen 失败后临时 fd 必须被关闭")
            self.assertEqual(open_fd_count(), self.baseline)
            self.assertBusinessStateUnchanged()
        finally:
            for fd in captured:
                self._close_quietly(fd)

    # ------------------------------------------------------------------
    # 2) write 失败
    # ------------------------------------------------------------------

    def test_write_failure(self):
        captured = []

        def wrapping_fdopen(fd, *args, **kwargs):
            captured.append(fd)
            self.assertIs(kwargs.get("closefd"), False)
            return _FaultyFile(_REAL_FDOPEN(fd, *args, **kwargs),
                               on_write="write failed")

        try:
            with mock.patch.object(main.os, "fdopen",
                                   side_effect=wrapping_fdopen):
                with self.assertRaises(OSError) as ctx:
                    main.modify_file("proj", "a.txt", "hello", "HELLO")

            self.assertIn("write failed", str(ctx.exception))
            self.assertFalse(_fd_is_open(captured[0]),
                             "write 失败后临时 fd 必须被关闭")
            self.assertEqual(open_fd_count(), self.baseline)
            self.assertBusinessStateUnchanged()
        finally:
            for fd in captured:
                self._close_quietly(fd)

    # ------------------------------------------------------------------
    # 3) flush 失败
    # ------------------------------------------------------------------

    def test_flush_failure(self):
        captured = []

        def wrapping_fdopen(fd, *args, **kwargs):
            captured.append(fd)
            self.assertIs(kwargs.get("closefd"), False)
            return _FaultyFile(_REAL_FDOPEN(fd, *args, **kwargs),
                               on_flush="flush failed")

        try:
            with mock.patch.object(main.os, "fdopen",
                                   side_effect=wrapping_fdopen):
                with self.assertRaises(OSError) as ctx:
                    main.modify_file("proj", "a.txt", "hello", "HELLO")

            self.assertIn("flush failed", str(ctx.exception))
            self.assertFalse(_fd_is_open(captured[0]),
                             "flush 失败后临时 fd 必须被关闭")
            self.assertEqual(open_fd_count(), self.baseline)
            self.assertBusinessStateUnchanged()
        finally:
            for fd in captured:
                self._close_quietly(fd)

    # ------------------------------------------------------------------
    # 4) fsync 失败（只命中临时 fd）
    # ------------------------------------------------------------------

    def test_fsync_failure(self):
        captured = []
        fsync_hits = []
        real_fsync = os.fsync

        def wrapping_fdopen(fd, *args, **kwargs):
            captured.append(fd)
            self.assertIs(kwargs.get("closefd"), False)
            return _REAL_FDOPEN(fd, *args, **kwargs)

        def failing_fsync(fd):
            if captured and fd == captured[0]:
                fsync_hits.append(fd)
                raise OSError(errno.EIO, "fsync failed")
            return real_fsync(fd)

        try:
            with mock.patch.object(main.os, "fdopen",
                                   side_effect=wrapping_fdopen), \
                    mock.patch.object(main.os, "fsync",
                                      side_effect=failing_fsync):
                with self.assertRaises(OSError) as ctx:
                    main.modify_file("proj", "a.txt", "hello", "HELLO")

            self.assertEqual(fsync_hits, [captured[0]],
                             "fsync 故障未命中临时 fd")
            self.assertIn("fsync failed", str(ctx.exception))
            self.assertFalse(_fd_is_open(captured[0]),
                             "fsync 失败后临时 fd 必须被关闭")
            self.assertEqual(open_fd_count(), self.baseline)
            self.assertBusinessStateUnchanged()
        finally:
            for fd in captured:
                self._close_quietly(fd)

    # ------------------------------------------------------------------
    # 5) 文件对象关闭失败，且 fd 关闭也失败
    # ------------------------------------------------------------------

    def test_file_object_close_failure(self):
        captured = []
        close_attempts = []

        def wrapping_fdopen(fd, *args, **kwargs):
            captured.append(fd)
            self.assertIs(kwargs.get("closefd"), False,
                          "必须以 closefd=False 创建底层文件对象")
            return _FaultyFile(_REAL_FDOPEN(fd, *args, **kwargs),
                               on_exit="file object close failed")

        def failing_close(fd):
            if captured and fd == captured[0]:
                close_attempts.append(fd)
                raise OSError(errno.EIO, _FD_CLOSE_ERROR)
            return _REAL_CLOSE(fd)

        try:
            with mock.patch.object(main.os, "fdopen",
                                   side_effect=wrapping_fdopen), \
                    mock.patch.object(main.os, "close",
                                      side_effect=failing_close):
                with self.assertRaises(OSError) as ctx:
                    main.modify_file("proj", "a.txt", "hello", "HELLO")

            self.assertEqual(close_attempts, [captured[0]],
                             "文件对象关闭失败后仍必须尝试关闭底层 fd")
            self.assertIn("file object close failed", str(ctx.exception))
            self.assertNotIn(_FD_CLOSE_ERROR, str(ctx.exception),
                             "fd 关闭异常不得覆盖文件对象关闭异常")
            self.assertTrue(_fd_is_open(captured[0]),
                            "closefd=False 下关闭文件对象不应关闭底层 fd")
            self.assertEqual(open_fd_count(), self.baseline + 1,
                             "除被注入的临时 fd 外不应有其他 fd 变化")
            self.assertBusinessStateUnchanged()
        finally:
            for fd in captured:
                self._close_quietly(fd)

    # ------------------------------------------------------------------
    # 6) 正常路径 fd 关闭失败
    # ------------------------------------------------------------------

    def test_normal_path_fd_close_failure(self):
        captured = []
        close_attempts = []

        def wrapping_fdopen(fd, *args, **kwargs):
            captured.append(fd)
            self.assertIs(kwargs.get("closefd"), False)
            return _REAL_FDOPEN(fd, *args, **kwargs)

        def failing_close(fd):
            if captured and fd == captured[0]:
                close_attempts.append(fd)
                raise OSError(errno.EIO, _FD_CLOSE_ERROR)
            return _REAL_CLOSE(fd)

        try:
            with mock.patch.object(main.os, "fdopen",
                                   side_effect=wrapping_fdopen), \
                    mock.patch.object(main.os, "close",
                                      side_effect=failing_close):
                with self.assertRaises(OSError) as ctx:
                    main.modify_file("proj", "a.txt", "hello", "HELLO")

            self.assertEqual(close_attempts, [captured[0]],
                             "正常路径必须尝试关闭临时 fd")
            self.assertIn(_FD_CLOSE_ERROR, str(ctx.exception),
                          "正常路径的关闭异常必须传播")
            self.assertTrue(_fd_is_open(captured[0]),
                            "mock 未真实关闭，fd 应仍然打开")
            self.assertEqual(open_fd_count(), self.baseline + 1,
                             "除被注入的临时 fd 外不应有其他 fd 变化")
            self.assertBusinessStateUnchanged()
        finally:
            for fd in captured:
                self._close_quietly(fd)

    # ------------------------------------------------------------------
    # 7) 异常路径 fd 关闭失败，原始异常仍保留
    # ------------------------------------------------------------------

    def test_error_path_fd_close_failure_preserves_original(self):
        captured = []
        close_attempts = []

        def failing_fdopen(fd, *args, **kwargs):
            captured.append(fd)
            self.assertIs(kwargs.get("closefd"), False,
                          "必须以 closefd=False 创建文件对象")
            raise OSError(errno.EIO, "fdopen failed")

        def failing_close(fd):
            if captured and fd == captured[0]:
                close_attempts.append(fd)
                raise OSError(errno.EIO, _FD_CLOSE_ERROR)
            return _REAL_CLOSE(fd)

        try:
            with mock.patch.object(main.os, "fdopen",
                                   side_effect=failing_fdopen), \
                    mock.patch.object(main.os, "close",
                                      side_effect=failing_close):
                with self.assertRaises(OSError) as ctx:
                    main.modify_file("proj", "a.txt", "hello", "HELLO")

            self.assertEqual(close_attempts, [captured[0]],
                             "异常路径仍必须尝试关闭 fd")
            self.assertIn("fdopen failed", str(ctx.exception),
                          "必须保留原始 fdopen 异常")
            self.assertNotIn(_FD_CLOSE_ERROR, str(ctx.exception),
                             "关闭异常不得覆盖原始异常")
            self.assertTrue(_fd_is_open(captured[0]),
                            "mock 未真实关闭，fd 应仍然打开")
            self.assertEqual(open_fd_count(), self.baseline + 1,
                             "除被注入的临时 fd 外不应有其他 fd 变化")
            self.assertBusinessStateUnchanged()
        finally:
            for fd in captured:
                self._close_quietly(fd)


if __name__ == "__main__":
    unittest.main()
