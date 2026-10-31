"""D-5.20-A1：目标文件锁与 inode 身份冲突检测。

覆盖：
1. 修改成功后锁被释放（连续两次修改可成功）；
2. 锁被占用时拒绝修改，且无任何副作用；
3. 修改失败后锁仍被释放；
4. 锁路径对同一目标稳定（不同写法归一到同一把锁）；
5. 锁文件位于仓库之外；
6. 目标被换成另一个 inode 时判定为冲突并停止；
7. 冲突时保留备份与原始文件，不留临时文件。
"""

import os
import subprocess
import sys
import unittest
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class ModifyLockTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.target = self.make_file(self.project, "a.txt", b"hello\n")
        self.grant("modify")

    def _resolved_target(self):
        return (self.project / "a.txt").resolve()

    def _backups(self):
        return sorted(self.project.glob("*.bak"))

    def _partials(self):
        return sorted(self.project.glob("*.partial"))

    # ------------------------------------------------------------------
    # 1) 正常修改后锁被释放
    # ------------------------------------------------------------------

    def test_lock_released_after_success(self):
        main.modify_file("proj", "a.txt", "hello", "HELLO")
        self.assertEqual(self.target.read_bytes(), b"HELLO\n")

        main.modify_file("proj", "a.txt", "HELLO", "HELLO2")
        self.assertEqual(self.target.read_bytes(), b"HELLO2\n")
        self.assertEqual(len(self._backups()), 2)

    # ------------------------------------------------------------------
    # 2) 锁被占用时拒绝修改
    # ------------------------------------------------------------------

    def test_busy_lock_blocks_modify(self):
        fd = main._acquire_target_lock(self._resolved_target())
        try:
            with self.assertRaises(main.TargetLockBusy):
                main.modify_file("proj", "a.txt", "hello", "HELLO")
        finally:
            main._release_target_lock(fd)

        self.assertEqual(self.target.read_bytes(), b"hello\n")
        self.assertEqual(self._backups(), [])
        self.assertEqual(self._partials(), [])

    # ------------------------------------------------------------------
    # 3) 失败后锁仍被释放
    # ------------------------------------------------------------------

    def test_lock_released_after_failure(self):
        with self.assertRaises(ValueError):
            main.modify_file("proj", "a.txt", "not-present", "X")

        # 若锁未释放，这里会抛 TargetLockBusy
        main.modify_file("proj", "a.txt", "hello", "HELLO")
        self.assertEqual(self.target.read_bytes(), b"HELLO\n")

    # ------------------------------------------------------------------
    # 4) 锁路径对同一目标稳定
    # ------------------------------------------------------------------

    def test_lock_path_is_stable_for_same_target(self):
        a = main._target_lock_path(self._resolved_target())
        b = main._target_lock_path((self.project / "./a.txt").resolve())
        self.assertEqual(a, b)

        other = main._target_lock_path((self.project / "b.txt").resolve())
        self.assertNotEqual(a, other)

    # ------------------------------------------------------------------
    # 5) 锁文件位于仓库之外
    # ------------------------------------------------------------------

    def test_lock_file_lives_outside_project(self):
        lock_dir = main._lock_dir()
        self.assertTrue(str(lock_dir).startswith(str(self.home)))
        self.assertFalse(str(lock_dir).startswith(str(self.project)))

        path = main._target_lock_path(self._resolved_target())
        self.assertEqual(path.parent, lock_dir)

    # ------------------------------------------------------------------
    # 6) inode 变化判定为冲突
    # ------------------------------------------------------------------

    def test_inode_change_detected_as_conflict(self):
        other = self.make_file(self.project, "other.txt", b"hello\n")
        real_open = main._open_target_no_follow
        calls = {"n": 0}

        def swap_on_recheck(path):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_open(path)
            # 第二次打开（复核）时给出另一个 inode，内容完全相同
            return os.open(str(other), os.O_RDONLY)

        with mock.patch.object(
            main, "_open_target_no_follow", side_effect=swap_on_recheck
        ):
            with self.assertRaises(main.ModifyConflictError) as ctx:
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertIn("inode", str(ctx.exception))
        self.assertGreaterEqual(calls["n"], 2)

    # ------------------------------------------------------------------
    # 7) 冲突时保留备份、原文件不变、无临时残留
    # ------------------------------------------------------------------

    def test_conflict_preserves_backup_and_original(self):
        other = self.make_file(self.project, "other.txt", b"hello\n")
        real_open = main._open_target_no_follow
        calls = {"n": 0}

        def swap_on_recheck(path):
            calls["n"] += 1
            if calls["n"] == 1:
                return real_open(path)
            return os.open(str(other), os.O_RDONLY)

        with mock.patch.object(
            main, "_open_target_no_follow", side_effect=swap_on_recheck
        ):
            with self.assertRaises(main.ModifyConflictError):
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertEqual(self.target.read_bytes(), b"hello\n")
        self.assertEqual(len(self._backups()), 1)
        self.assertEqual(self._backups()[0].read_bytes(), b"hello\n")
        self.assertEqual(self._partials(), [])
        self.assertEqual(list(self.project.glob("*.tmp")), [])


    # ------------------------------------------------------------------
    # 8) 真正的跨进程互斥（子进程持锁，父进程被拒）
    # ------------------------------------------------------------------

    def test_cross_process_lock_is_exclusive(self):
        lock_path = main._target_lock_path(self._resolved_target())
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        child_code = (
            "import fcntl, os, sys, time\n"
            "fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)\n"
            "fcntl.flock(fd, fcntl.LOCK_EX)\n"
            "print('LOCKED', flush=True)\n"
            "time.sleep(10)\n"
        )

        child = subprocess.Popen(
            [sys.executable, "-c", child_code, str(lock_path)],
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            line = child.stdout.readline().strip()
            self.assertEqual(line, "LOCKED")

            with self.assertRaises(main.TargetLockBusy):
                main.modify_file("proj", "a.txt", "hello", "HELLO")
        finally:
            child.kill()
            child.wait(timeout=10)
            child.stdout.close()

        self.assertEqual(self.target.read_bytes(), b"hello\n")
        self.assertEqual(self._backups(), [])

        # 子进程退出后锁自动释放
        main.modify_file("proj", "a.txt", "hello", "HELLO")
        self.assertEqual(self.target.read_bytes(), b"HELLO\n")


if __name__ == "__main__":
    unittest.main()
