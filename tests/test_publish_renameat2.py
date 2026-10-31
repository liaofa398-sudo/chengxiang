"""C3 最终形态：renameat2(RENAME_NOREPLACE) 严格发布。

覆盖：正常发布、EEXIST 换名、候选耗尽、原语不可用与各类 fatal errno 的
fail-closed、以及"已发布但父目录 fsync 失败"这一独立的持久性状态。
"""

import ctypes
import errno
import io
import os
import threading
import unittest
from contextlib import redirect_stdout
from unittest import mock

import main
from tests.support import ChengxiangTestBase


def _failing_rename(err):
    """构造一个总是失败的 renameat2 替身，并把 errno 写进 ctypes。"""
    def fn(olddirfd, oldpath, newdirfd, newpath, flags):
        ctypes.set_errno(err)
        return -1
    return fn


class PublishConcurrencyTests(ChengxiangTestBase):
    def test_two_publishers_same_name_only_one_wins(self):
        project = self.setup_project("proj")
        self.grant("modify")
        target = self.make_file(project, "a.txt", b"x\n")
        fixed = project / "same.before_chengxiang_modify.bak"

        sources = []
        for index in range(2):
            path = project / f"s{index}.before_chengxiang_modify.partial"
            path.write_bytes(b"data-%d" % index)
            sources.append(path)

        barrier = threading.Barrier(2)
        outcomes = []

        def worker(source):
            barrier.wait()
            try:
                outcomes.append(("ok", main._publish_backup(source, target)))
            except main.BackupPublishError as exc:
                outcomes.append(("err", exc))

        with mock.patch.object(
            main, "_make_backup_candidate", return_value=fixed
        ):
            threads = [
                threading.Thread(target=worker, args=(s,)) for s in sources
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

        winners = [item for item in outcomes if item[0] == "ok"]
        self.assertEqual(len(winners), 1, "同一目标名最多只能有一个发布者成功")
        self.assertTrue(fixed.exists())
        self.assertEqual(
            sum(1 for s in sources if s.exists()), 1, "失败者的源必须保留"
        )


class PublishSuccessTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")

    def test_publish_moves_partial_to_official_and_keeps_bytes(self):
        original = b"hello\r\nworld\r\n"
        target = self.make_file(self.project, "a.txt", original)

        with redirect_stdout(io.StringIO()):
            result = main.modify_file("proj", "a.txt", "hello", "HELLO")

        with open(result["backup"], "rb") as handle:
            self.assertEqual(handle.read(), original, "备份必须逐字节一致")

        self.assertEqual(self.partials(self.project), [], "不得残留 .partial")
        self.assertEqual(len(self.backups(self.project)), 1)
        self.assertEqual(
            target.read_bytes(), b"HELLO\r\nworld\r\n"
        )

    def test_official_name_published_by_rename_not_copy(self):
        """rename 是移动：发布后 .partial 这个 inode 名不复存在。"""
        target = self.make_file(self.project, "b.txt", b"x\n")
        partial_path = self.project / "b.txt.1.partial"
        partial_path.write_bytes(b"x\n")

        official = main._publish_backup(partial_path, target)

        self.assertTrue(official.name.endswith(".before_chengxiang_modify.bak"))
        self.assertFalse(partial_path.exists())
        self.assertEqual(official.read_bytes(), b"x\n")


class PublishConflictTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")
        self.make_file(self.project, "a.txt", b"hello\n")

    def test_eexist_takes_next_candidate_and_keeps_existing(self):
        existing = self.make_file(self.project, "occupied.bak", b"keep")
        fresh = self.project / "fresh.bak"
        candidates = iter([existing, existing, fresh])

        with mock.patch.object(
            main, "_make_backup_candidate",
            side_effect=lambda *a: next(candidates),
        ), redirect_stdout(io.StringIO()):
            result = main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertEqual(existing.read_bytes(), b"keep", "旧备份不得被覆盖")
        self.assertEqual(result["backup"], str(fresh))
        self.assertTrue(fresh.exists())

    def test_all_candidates_occupied_refuses_and_keeps_partial(self):
        target = self.make_file(self.project, "a.txt", b"hello\n")
        existing = self.make_file(self.project, "occupied.bak", b"keep")

        with mock.patch.object(
            main, "_make_backup_candidate", return_value=existing
        ), redirect_stdout(io.StringIO()):
            with self.assertRaises(main.BackupPublishError):
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertEqual(existing.read_bytes(), b"keep")
        self.assertEqual(self.backups(self.project), [])
        self.assertEqual(
            len([p for p in self.project.iterdir() if p.name.endswith(".partial")]),
            1,
            "半成品必须保留",
        )
        self.assertEqual(target.read_bytes(), b"hello\n")

    def test_old_backup_never_overwritten_across_runs(self):
        self.make_file(self.project, "a.txt", b"hello\n")
        with redirect_stdout(io.StringIO()):
            first = main.modify_file("proj", "a.txt", "hello", "HELLO")
            second = main.modify_file("proj", "a.txt", "HELLO", "HI")
        self.assertNotEqual(first["backup"], second["backup"])
        with open(first["backup"], "rb") as handle:
            self.assertEqual(handle.read(), b"hello\n")
        with open(second["backup"], "rb") as handle:
            self.assertEqual(handle.read(), b"HELLO\n")


class PublishFailClosedTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")
        self.target = self.make_file(self.project, "a.txt", b"hello\n")

    def _assert_fail_closed(self):
        self.assertEqual(self.backups(self.project), [], "不得产生正式 .bak")
        self.assertEqual(len(self.partials(self.project)), 1, "半成品必须保留")
        self.assertEqual(self.target.read_bytes(), b"hello\n", "原文件不得被修改")

    def test_unavailable_primitive_is_refused(self):
        with mock.patch.object(main, "_load_renameat2", return_value=None), \
                redirect_stdout(io.StringIO()):
            with self.assertRaises(main.BackupPublishError) as ctx:
                main.modify_file("proj", "a.txt", "hello", "HELLO")
        self.assertIn("不提供", str(ctx.exception))
        self._assert_fail_closed()

    def test_fatal_errnos_are_fail_closed(self):
        codes = (
            errno.ENOSYS,
            errno.EINVAL,
            errno.EOPNOTSUPP,
            errno.EPERM,
            errno.EACCES,
        )
        for index, code in enumerate(codes):
            with self.subTest(errno=code):
                name = f"f{index}.txt"
                target = self.make_file(self.project, name, b"hello\n")

                with mock.patch.object(
                    main, "_load_renameat2",
                    return_value=_failing_rename(code),
                ), redirect_stdout(io.StringIO()):
                    with self.assertRaises(main.BackupPublishError) as ctx:
                        main.modify_file("proj", name, "hello", "HELLO")

                self.assertIn("拒绝降级", str(ctx.exception))
                self.assertEqual(self.backups(self.project), [])
                self.assertEqual(target.read_bytes(), b"hello\n")
                self.assertEqual(
                    len(self.partials(self.project)), index + 1
                )

    def test_other_errno_reports_code(self):
        with mock.patch.object(
            main, "_load_renameat2",
            return_value=_failing_rename(errno.ENOENT),
        ), redirect_stdout(io.StringIO()):
            with self.assertRaises(main.BackupPublishError) as ctx:
                main.modify_file("proj", "a.txt", "hello", "HELLO")
        self.assertIn("ENOENT", str(ctx.exception))
        self._assert_fail_closed()


class DirectoryFsyncTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")

    def test_directory_fsync_success_completes_normally(self):
        target = self.make_file(self.project, "a.txt", b"hello\n")
        with redirect_stdout(io.StringIO()):
            result = main.modify_file("proj", "a.txt", "hello", "HELLO")
        self.assertTrue(os.path.exists(result["backup"]))
        self.assertEqual(target.read_bytes(), b"HELLO\n")

    def test_directory_fsync_failure_raises_durability_error(self):
        with mock.patch.object(
            main.os, "fsync", side_effect=OSError(errno.EIO, "io")
        ):
            with self.assertRaises(main.BackupDurabilityError):
                main._fsync_directory(self.project, "some.bak")

    def test_published_backup_survives_durability_failure(self):
        """已发布但持久性未确认：不得删除 .bak，也不得声称其不存在。"""
        target = self.make_file(self.project, "a.txt", b"hello\n")

        with mock.patch.object(
            main, "_fsync_directory",
            side_effect=main.BackupDurabilityError("持久性未确认"),
        ), redirect_stdout(io.StringIO()):
            with self.assertRaises(main.BackupDurabilityError):
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        created = self.backups(self.project)
        self.assertEqual(len(created), 1, "正式 .bak 已经出现，不得删除")
        self.assertEqual(created[0].read_bytes(), b"hello\n")
        self.assertEqual(self.partials(self.project), [], "rename 已移走源")
        self.assertEqual(target.read_bytes(), b"hello\n", "原文件不得被修改")

    def test_durability_error_is_backup_publish_error(self):
        self.assertTrue(
            issubclass(main.BackupDurabilityError, main.BackupPublishError)
        )


class PartialIdentityTests(ChengxiangTestBase):
    """D-1：发布前必须确认 .partial 仍是本次创建并写入的那个 inode。"""

    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")
        self.target = self.make_file(self.project, "a.txt", b"hello\n")
        self.partial_path = (
            self.project / "fixed.before_chengxiang_modify.partial"
        )

    def _run(self, swap=None, record=None):
        """在 .partial 写完并 fsync 的那一刻执行 swap，然后继续原流程。"""
        real_fsync = os.fsync
        state = {"fired": False}

        def hook(fd):
            if not state["fired"]:
                state["fired"] = True
                if record is not None:
                    # 用 fsync 收到的 fd 取身份，即实现自身看到的"源文件"，
                    # 而不是按路径 lstat（后者在路径被替换时会给出错误答案）。
                    info = os.fstat(fd)
                    record["dev"] = info.st_dev
                    record["ino"] = info.st_ino
                if swap is not None:
                    if (self.partial_path.exists()
                            or self.partial_path.is_symlink()):
                        os.unlink(self.partial_path)
                    swap()
            return real_fsync(fd)

        with mock.patch.object(
            main, "_make_partial_candidate", return_value=self.partial_path
        ), mock.patch.object(
            main.os, "fsync", side_effect=hook
        ), redirect_stdout(io.StringIO()):
            return main.modify_file("proj", "a.txt", "hello", "HELLO")

    def _run_expecting_failure(self, swap):
        with self.assertRaises(main.BackupPublishError) as ctx:
            self._run(swap=swap)
        return ctx.exception

    def test_identity_consistent_publishes_normally(self):
        result = self._run()

        self.assertEqual(len(self.backups(self.project)), 1)
        self.assertFalse(self.partial_path.exists())
        with open(result["backup"], "rb") as handle:
            self.assertEqual(handle.read(), b"hello\n")
        self.assertEqual(self.target.read_bytes(), b"HELLO\n")

    def test_publish_is_rename_not_copy_after_verification(self):
        """发布必须是同 inode 的移动，而不是复制后删除源。

        身份取自 .partial 打开后的 fd（fstat），而非路径 lstat；
        发布后要求正式 .bak 的 (st_dev, st_ino) 与之完全一致。
        """
        record = {}
        result = self._run(record=record)

        info = os.stat(result["backup"])
        self.assertEqual(
            (info.st_dev, info.st_ino),
            (record["dev"], record["ino"]),
            "正式备份必须是 .partial 的同一 inode（renameat2 移动）",
        )
        self.assertFalse(self.partial_path.exists())

    def test_replaced_by_regular_file_is_refused(self):
        def swap():
            self.partial_path.write_bytes(b"attacker-payload")

        error = self._run_expecting_failure(swap)

        self.assertIn("verify", str(error))
        self.assertEqual(self.backups(self.project), [], "不得发布正式 .bak")
        self.assertEqual(self.target.read_bytes(), b"hello\n")
        self.assertTrue(self.partial_path.exists(), "被替换的对象不得被删除")
        self.assertEqual(
            self.partial_path.read_bytes(), b"attacker-payload"
        )

    def test_replaced_by_symlink_is_refused_and_not_followed(self):
        victim = self.project / "victim.txt"
        victim.write_bytes(b"victim-data")

        def swap():
            os.symlink(str(victim), str(self.partial_path))

        error = self._run_expecting_failure(swap)

        self.assertIn("符号链接", str(error))
        self.assertTrue(self.partial_path.is_symlink(), "链接本身不得被删除")
        self.assertEqual(victim.read_bytes(), b"victim-data")
        self.assertEqual(self.backups(self.project), [])
        self.assertEqual(self.target.read_bytes(), b"hello\n")

    def test_deleted_partial_is_refused(self):
        def swap():
            pass  # 只删除，不重建

        error = self._run_expecting_failure(swap)

        self.assertIn("不存在", str(error))
        self.assertEqual(self.backups(self.project), [])
        self.assertEqual(self.target.read_bytes(), b"hello\n")

    def test_identity_failure_creates_no_official_backup_at_all(self):
        def swap():
            self.partial_path.write_bytes(b"x")

        self._run_expecting_failure(swap)

        names = [p.name for p in self.project.iterdir()]
        self.assertFalse(
            any(n.endswith(".before_chengxiang_modify.bak") for n in names),
            f"不得出现任何正式 .bak：{names}",
        )


if __name__ == "__main__":
    unittest.main()
