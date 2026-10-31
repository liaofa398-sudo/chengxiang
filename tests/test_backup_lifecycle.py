"""F2：备份生命周期。

规则：每次修改创建独立备份；完整备份成功后保留；
失败时保留半成品；不存在任何删除备份的代码路径。
"""

import contextlib
import errno
import fnmatch
import inspect
import io
import os
import unittest
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class BackupLifecycleTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.target = self.make_file(
            self.project, "a.txt", b"hello\nworld\n"
        )
        self.grant("modify")

    def test_two_modifications_create_two_independent_backups(self):
        main.modify_file("proj", "a.txt", "hello", "HELLO")
        main.modify_file("proj", "a.txt", "world", "WORLD")

        backups = self.backups(self.project)
        self.assertEqual(len(backups), 2)
        self.assertNotEqual(backups[0].name, backups[1].name)

        contents = sorted(p.read_bytes() for p in backups)
        self.assertEqual(
            contents, [b"HELLO\nworld\n", b"hello\nworld\n"]
        )
        self.assertEqual(self.target.read_bytes(), b"HELLO\nWORLD\n")

    def test_backup_name_matches_gitignore_pattern(self):
        result = main.modify_file("proj", "a.txt", "hello", "HELLO")
        name = os.path.basename(result["backup"])
        self.assertTrue(fnmatch.fnmatch(name, "*.bak"))
        self.assertTrue(os.path.exists(result["backup"]))

    def test_partial_backup_is_kept_and_warned(self):
        out = io.StringIO()
        with mock.patch.object(
            main.os, "fchmod", side_effect=OSError(errno.EIO, "io")
        ):
            with contextlib.redirect_stdout(out):
                with self.assertRaises(OSError):
                    main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertEqual(
            self.backups(self.project), [], "不得产生正式 .bak"
        )
        self.assertEqual(
            len(self.partials(self.project)), 1,
            "半成品必须以 .partial 保留",
        )
        self.assertIn("不做自动清理", out.getvalue())
        self.assertEqual(self.target.read_bytes(), b"hello\nworld\n")

    def test_partial_backup_failure_attaches_note(self):
        with mock.patch.object(
            main.os, "fchmod", side_effect=OSError(errno.EIO, "io")
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                try:
                    main.modify_file("proj", "a.txt", "hello", "HELLO")
                except OSError as exc:
                    notes = getattr(exc, "__notes__", [])
                    self.assertTrue(
                        any(".partial" in n for n in notes),
                        f"异常未附注半成品路径：{notes}",
                    )
                else:
                    self.fail("应当抛出异常")

    def test_no_unlink_is_ever_called_on_backup_path(self):
        recorded = []
        real_unlink = os.unlink

        def spy(path, *args, **kwargs):
            recorded.append(str(path))
            return real_unlink(path, *args, **kwargs)

        with mock.patch("os.unlink", side_effect=spy):
            with mock.patch.object(
                main.os, "fchmod", side_effect=OSError(errno.EIO, "io")
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaises(OSError):
                        main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertFalse(
            any(".bak" in p for p in recorded),
            f"备份路径不应被删除：{recorded}",
        )

    def test_abandon_helper_contains_no_deletion(self):
        source = inspect.getsource(main._abandon_partial_backup)
        for token in ("unlink", "remove(", "os.replace", "rmtree"):
            self.assertNotIn(token, source)

    def test_unlink_spy_works_and_targets_only_temp_file(self):
        """对照组：证明探针有效——临时文件会被 unlink，备份不会。"""
        recorded = []
        real_unlink = os.unlink

        def spy(path, *args, **kwargs):
            recorded.append(str(path))
            return real_unlink(path, *args, **kwargs)

        with mock.patch("os.unlink", side_effect=spy):
            with mock.patch.object(
                main.os, "replace", side_effect=OSError(errno.EIO, "io")
            ):
                with self.assertRaises(OSError):
                    main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertTrue(
            any(".chengxiang_tmp_" in p for p in recorded),
            "临时文件应被清理，证明探针有效",
        )
        self.assertFalse(any(".bak" in p for p in recorded))

    def test_complete_backup_survives_later_failure(self):
        with mock.patch.object(
            main.os, "replace", side_effect=OSError(errno.EIO, "io")
        ):
            with self.assertRaises(OSError):
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        backups = self.backups(self.project)
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), b"hello\nworld\n")
        self.assertEqual(self.target.read_bytes(), b"hello\nworld\n")

    def test_collision_regenerates_candidate(self):
        existing = self.make_file(self.project, "occupied.bak", b"old")
        fresh = self.project / "fresh.bak"
        candidates = iter([existing, fresh, fresh, fresh, fresh])

        with mock.patch.object(
            main, "_make_backup_candidate", side_effect=lambda *a: next(candidates)
        ):
            result = main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertEqual(result["backup"], str(fresh))
        self.assertEqual(existing.read_bytes(), b"old", "既有文件不得被覆盖")

    def test_all_attempts_collide_raises(self):
        existing = self.make_file(self.project, "occupied.bak", b"old")
        with mock.patch.object(
            main, "_make_backup_candidate", return_value=existing
        ):
            with self.assertRaises(RuntimeError):
                main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertEqual(self.target.read_bytes(), b"hello\nworld\n")
        self.assertEqual(existing.read_bytes(), b"old")

    def test_retry_after_failure_succeeds(self):
        with mock.patch.object(
            main.os, "fchmod", side_effect=OSError(errno.EIO, "io")
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(OSError):
                    main.modify_file("proj", "a.txt", "hello", "HELLO")

        main.modify_file("proj", "a.txt", "hello", "HELLO")
        self.assertEqual(self.target.read_bytes(), b"HELLO\nworld\n")
        self.assertEqual(len(self.backups(self.project)), 1)
        self.assertEqual(len(self.partials(self.project)), 1)

    def test_write_failure_leaves_no_official_backup(self):
        with mock.patch.object(
            main.os, "fsync", side_effect=OSError(errno.EIO, "io")
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(OSError):
                    main.modify_file("proj", "a.txt", "hello", "HELLO")

        self.assertEqual(self.backups(self.project), [])
        self.assertEqual(len(self.partials(self.project)), 1)
        self.assertEqual(self.target.read_bytes(), b"hello\nworld\n")

    def test_publish_does_not_overwrite_existing_official_backup(self):
        existing = self.make_file(self.project, "occupied.bak", b"keep")
        fresh = self.project / "fresh.bak"
        candidates = iter([existing, existing, fresh])

        with mock.patch.object(
            main, "_make_backup_candidate",
            side_effect=lambda *a: next(candidates),
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                result = main.modify_file(
                    "proj", "a.txt", "hello", "HELLO"
                )

        self.assertEqual(existing.read_bytes(), b"keep", "既有文件不得被覆盖")
        self.assertEqual(result["backup"], str(fresh))
        self.assertTrue(fresh.exists())
        self.assertEqual(self.target.read_bytes(), b"HELLO\nworld\n")

    def test_published_backup_is_byte_identical(self):
        original = b"\xef\xbb\xbfa\r\nb\r\n"
        target = self.make_file(self.project, "bom.txt", original)

        with contextlib.redirect_stdout(io.StringIO()):
            result = main.modify_file("proj", "bom.txt", "a", "A")

        with open(result["backup"], "rb") as handle:
            self.assertEqual(handle.read(), original)
        self.assertEqual(target.read_bytes(), b"\xef\xbb\xbfA\r\nb\r\n")
        self.assertEqual(self.partials(self.project), [])


if __name__ == "__main__":
    unittest.main()
