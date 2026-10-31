"""F3：备份权限不得宽于原文件，且保留可执行位。"""

import os
import stat
import unittest

import main
from tests.support import ChengxiangTestBase


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


class BackupModeTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")

    def _modify_with_mode(self, original_mode):
        target = self.make_file(
            self.project, "f.txt", b"hello\n", mode=original_mode
        )
        result = main.modify_file("proj", "f.txt", "hello", "HELLO")
        return target, os.stat(result["backup"])

    def test_private_file_stays_private(self):
        target, backup_stat = self._modify_with_mode(0o600)
        self.assertEqual(stat.S_IMODE(backup_stat.st_mode), 0o600)
        self.assertEqual(mode_of(target), 0o600)

    def test_executable_bit_is_preserved(self):
        target, backup_stat = self._modify_with_mode(0o755)
        self.assertEqual(stat.S_IMODE(backup_stat.st_mode), 0o755)
        self.assertEqual(mode_of(target), 0o755)

    def test_no_executable_bit_is_added(self):
        target, backup_stat = self._modify_with_mode(0o644)
        self.assertEqual(stat.S_IMODE(backup_stat.st_mode), 0o644)
        self.assertFalse(backup_stat.st_mode & 0o111)

    def test_mode_0700(self):
        _, backup_stat = self._modify_with_mode(0o700)
        self.assertEqual(stat.S_IMODE(backup_stat.st_mode), 0o700)

    def test_read_execute_file(self):
        _, backup_stat = self._modify_with_mode(0o500)
        self.assertEqual(stat.S_IMODE(backup_stat.st_mode), 0o500)

    def test_backup_mode_is_umask_independent(self):
        old_umask = os.umask(0o000)
        try:
            target = self.make_file(
                self.project, "u.txt", b"hello\n", mode=0o600
            )
            result = main.modify_file("proj", "u.txt", "hello", "HELLO")
        finally:
            os.umask(old_umask)

        self.assertEqual(mode_of(result["backup"]), 0o600)
        self.assertEqual(mode_of(target), 0o600)

    def test_backup_never_wider_than_original(self):
        for original_mode in (
            0o400, 0o500, 0o600, 0o640, 0o644,
            0o700, 0o750, 0o755, 0o775, 0o777,
        ):
            with self.subTest(mode=oct(original_mode)):
                target = self.make_file(
                    self.project,
                    f"m{original_mode:o}.txt",
                    b"hello\n",
                    mode=original_mode,
                )
                result = main.modify_file(
                    "proj", f"m{original_mode:o}.txt", "hello", "HELLO"
                )
                backup_mode = mode_of(result["backup"])
                self.assertEqual(
                    backup_mode & ~original_mode,
                    0,
                    f"备份 {oct(backup_mode)} 宽于原文件 {oct(original_mode)}",
                )
                self.assertEqual(mode_of(target), original_mode)

    def test_special_bits_are_stripped_from_backup_mode(self):
        self.assertEqual(stat.S_IMODE(0o4755) & 0o777, 0o755)
        self.assertEqual(stat.S_IMODE(0o2755) & 0o777, 0o755)


if __name__ == "__main__":
    unittest.main()
