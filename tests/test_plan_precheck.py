"""F8：计划层预检必须走安全路径解析，PermissionError 必须冒泡。"""

import os
import unittest
from unittest import mock

import main
from tests.support import ChengxiangTestBase


def plan_line(tool, args):
    import json

    payload = {
        "tools": [
            {"name": tool, "project_id": "proj", "args": args}
        ]
    }
    return "TOOL_PLAN_JSON: " + json.dumps(payload, ensure_ascii=False)


class PlanPrecheckTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        main.AUTHORIZED_PERMISSION = "read"

    def test_large_file_without_range_is_rejected(self):
        self.make_file(self.project, "big.txt", b"x" * 40000)
        with self.assertRaises(PermissionError) as ctx:
            main.parse_tool_plan(plan_line("read_file", {"relative_path": "big.txt"}))
        self.assertIn("30000", str(ctx.exception))

    def test_large_file_with_range_is_allowed(self):
        self.make_file(self.project, "big.txt", b"x" * 40000)
        plan = main.parse_tool_plan(
            plan_line(
                "read_file",
                {"relative_path": "big.txt", "start_line": 1, "end_line": 5},
            )
        )
        self.assertEqual(len(plan), 1)

    def test_escaping_path_does_not_raise_and_leaks_no_size(self):
        # ../../../.. 从临时项目的父目录向上，最终落到 / 之下
        plan = main.parse_tool_plan(
            plan_line("read_file", {"relative_path": "../../../../etc/hostname"})
        )
        self.assertEqual(len(plan), 1)

    def test_project_without_local_path_is_skipped(self):
        self.write_projects({"proj": {"name": "proj", "path": None}})
        plan = main.parse_tool_plan(plan_line("read_file", {"relative_path": "x.txt"}))
        self.assertEqual(len(plan), 1)

    def test_permission_error_from_safe_path_propagates(self):
        self.write_projects(
            {"proj": {"name": "proj", "path": str(main.BASE_DIR)}}
        )
        with self.assertRaises(PermissionError):
            main.parse_tool_plan(
                plan_line("read_file", {"relative_path": "anything.txt"})
            )

    def test_symlink_loop_degrades_safely(self):
        loop_a = self.project / "loop_a"
        loop_b = self.project / "loop_b"
        os.symlink("loop_b", str(loop_a))
        os.symlink("loop_a", str(loop_b))

        # 不应抛出任何异常：链接循环属于"明确无效路径"，安全降级跳过。
        plan = main.parse_tool_plan(
            plan_line("read_file", {"relative_path": "loop_a"})
        )
        self.assertEqual(len(plan), 1)

    def test_precheck_never_stats_outside_root(self):
        self.make_file(self.project, "small.txt", b"ok\n")
        original_stat = os.stat

        def spy(path, *args, **kwargs):
            result = original_stat(path, *args, **kwargs)
            return result

        with mock.patch("os.stat", side_effect=spy) as patched:
            main.parse_tool_plan(
                plan_line(
                    "read_file",
                    {"relative_path": "../../../../etc/hostname"},
                )
            )

        for call in patched.call_args_list:
            target = str(call.args[0])
            self.assertFalse(
                target == "/etc/hostname",
                "预检不得对项目外路径执行 stat",
            )


if __name__ == "__main__":
    unittest.main()
