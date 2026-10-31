"""F5：拒绝修改带 setuid/setgid 特殊权限的文件。"""

import os
import stat
import unittest

import main
from tests.support import ChengxiangTestBase


class SpecialModeTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.grant("modify")

    def _set_mode_or_skip(self, path, mode):
        os.chmod(path, mode)
        if stat.S_IMODE(os.stat(path).st_mode) != mode:
            self.skipTest("当前文件系统不支持设置该特殊权限位")

    def test_setuid_file_is_rejected(self):
        target = self.make_file(self.project, "suid.bin", b"hello\n")
        self._set_mode_or_skip(target, 0o4755)

        with self.assertRaises(PermissionError) as ctx:
            main.modify_file("proj", "suid.bin", "hello", "HELLO")

        self.assertIn("setuid", str(ctx.exception))
        self.assertEqual(target.read_bytes(), b"hello\n")
        self.assertEqual(self.backups(self.project), [])

    def test_setgid_file_is_rejected(self):
        """真实普通文件（非符号链接）的 setgid：必须在这一路径上被拒绝。"""
        target = self.make_file(self.project, "sgid.bin", b"hello\n")
        self._set_mode_or_skip(target, 0o2755)
        self.assertFalse(target.is_symlink(), "本用例必须走普通文件路径")

        with self.assertRaises(PermissionError) as ctx:
            main.modify_file("proj", "sgid.bin", "hello", "HELLO")

        self.assertIn("setgid", str(ctx.exception), "拒绝原因必须是 setgid 检查")
        self.assertEqual(target.read_bytes(), b"hello\n")
        self.assertEqual(self.backups(self.project), [], "不得产生正式 .bak")
        self.assertEqual(self.partials(self.project), [], "不得产生 .partial")

    def test_setuid_and_setgid_together_are_rejected(self):
        target = self.make_file(self.project, "both.bin", b"hello\n")
        self._set_mode_or_skip(target, 0o6755)

        with self.assertRaises(PermissionError):
            main.modify_file("proj", "both.bin", "hello", "HELLO")

    def test_rejection_happens_through_symlink(self):
        target = self.make_file(self.project, "real.bin", b"hello\n")
        self._set_mode_or_skip(target, 0o2755)
        os.symlink(str(target), str(self.project / "link.bin"))

        with self.assertRaises(PermissionError):
            main.modify_file("proj", "link.bin", "hello", "HELLO")

    def test_normal_file_still_modifiable(self):
        target = self.make_file(
            self.project, "plain.txt", b"hello\n", mode=0o644
        )
        main.modify_file("proj", "plain.txt", "hello", "HELLO")
        self.assertEqual(target.read_bytes(), b"HELLO\n")


if __name__ == "__main__":
    unittest.main()
