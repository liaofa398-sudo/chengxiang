"""F1：项目路径边界（Home / 自身目录 / 别名）。

对应 main.safe_project_path 与 main._stat_identity。
"""

import errno
import os
import unittest
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class StatIdentityTests(ChengxiangTestBase):
    """_stat_identity 的失败分类：不存在 vs 无法确认。"""

    def test_missing_path_returns_none(self):
        self.assertIsNone(main._stat_identity(self.tmp / "does-not-exist"))

    def test_not_a_directory_returns_none(self):
        plain = self.tmp / "plain.txt"
        plain.write_text("x", encoding="utf-8")
        self.assertIsNone(main._stat_identity(plain / "child"))

    def test_real_directory_returns_inode_pair(self):
        identity = main._stat_identity(self.tmp)
        self.assertIsInstance(identity, tuple)
        self.assertEqual(len(identity), 2)

    def test_permission_error_is_fatal(self):
        with mock.patch.object(
            main.os, "stat", side_effect=PermissionError(errno.EACCES, "denied")
        ):
            with self.assertRaises(PermissionError):
                main._stat_identity(self.tmp)

    def test_io_error_is_fatal(self):
        with mock.patch.object(
            main.os, "stat", side_effect=OSError(errno.EIO, "io error")
        ):
            with self.assertRaises(PermissionError):
                main._stat_identity(self.tmp)


class AliasBoundaryTests(ChengxiangTestBase):
    """边界三：同一文件系统对象的不同路径拼写。"""

    def test_same_identity_is_rejected(self):
        """回归：拒绝必须真的抛出去，不能被 except OSError 吞掉。"""
        target = self.make_project_dir("proj")
        with mock.patch.object(main, "_stat_identity", return_value=(1, 1)):
            with self.assertRaises(PermissionError):
                main.safe_project_path({"path": str(target)})

    def test_ancestor_identity_is_rejected(self):
        target = self.make_project_dir("proj")

        def fake(path):
            if str(path) == str(target):
                return (7, 7)
            if str(path) == str(self.home):
                return (7, 7)
            return (8, 8)

        with mock.patch.object(main, "_stat_identity", side_effect=fake):
            with self.assertRaises(PermissionError):
                main.safe_project_path({"path": str(target)})

    def test_distinct_identity_is_accepted(self):
        target = self.make_project_dir("proj")
        seen = {}

        def fake(path):
            key = str(path)
            if key not in seen:
                seen[key] = (len(seen) + 1, 1)
            return seen[key]

        with mock.patch.object(main, "_stat_identity", side_effect=fake):
            self.assertEqual(
                main.safe_project_path({"path": str(target)}), target
            )


class LiteralBoundaryTests(ChengxiangTestBase):
    """边界一与边界二：Home、自身、祖先、子孙。"""

    def test_empty_path_returns_none(self):
        self.assertIsNone(main.safe_project_path({}))
        self.assertIsNone(main.safe_project_path({"path": None}))
        self.assertIsNone(main.safe_project_path({"path": ""}))

    def test_outside_home_is_rejected(self):
        with self.assertRaises(PermissionError):
            main.safe_project_path({"path": str(self.tmp)})

    def test_self_directory_is_rejected(self):
        with self.assertRaises(PermissionError):
            main.safe_project_path({"path": str(main.BASE_DIR)})

    def test_ancestor_directory_is_rejected(self):
        with self.assertRaises(PermissionError):
            main.safe_project_path({"path": str(self.home)})

    def test_descendant_directory_is_rejected(self):
        child = main.BASE_DIR / "sub"
        child.mkdir()
        with self.assertRaises(PermissionError):
            main.safe_project_path({"path": str(child)})

    def test_symlink_to_base_dir_is_rejected(self):
        link = self.home / "link"
        os.symlink(str(main.BASE_DIR), str(link))
        with self.assertRaises(PermissionError):
            main.safe_project_path({"path": str(link)})

    def test_normal_sibling_is_accepted(self):
        target = self.make_project_dir("proj")
        resolved = main.safe_project_path({"path": str(target)})
        self.assertEqual(resolved, target.resolve())

    def test_nonexistent_sibling_is_accepted(self):
        ghost = self.home / "ghost"
        resolved = main.safe_project_path({"path": str(ghost)})
        self.assertEqual(resolved, ghost)

    def test_base_dir_is_read_at_call_time(self):
        """BASE_DIR 必须可被测试替换，而不是导入期固化。"""
        new_base = self.home / "newbase"
        new_base.mkdir()
        main.BASE_DIR = new_base
        with self.assertRaises(PermissionError):
            main.safe_project_path({"path": str(new_base)})


if __name__ == "__main__":
    unittest.main()
