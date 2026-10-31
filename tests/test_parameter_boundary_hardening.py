"""D-5.14-A1：参数边界最小修复（P2-3 / P2-4）。

P2-3：read_file 的 start_line 类型校验必须早于 `start_line + 200`。
P2-4：parse_tool_plan 必须在项目注册表查询前拒绝非字符串 project_id。

全部用例使用 ChengxiangTestBase 的临时 HOME / BASE_DIR，
不访问真实项目文件、网络或凭据。
"""

import json
import unittest

import main
from tests.support import ChengxiangTestBase


def plan_line(tool, args, project_id="proj"):
    payload = {
        "tools": [
            {"name": tool, "project_id": project_id, "args": args}
        ]
    }
    return "TOOL_PLAN_JSON: " + json.dumps(payload, ensure_ascii=False)


class ReadFileLineNumberOrderTests(ChengxiangTestBase):
    """P2-3：start_line 类型校验早于任何加法运算。"""

    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.make_file(self.project, "a.txt", b"line1\nline2\nline3\n")
        main.AUTHORIZED_PERMISSION = "read"

    def test_rejects_string_start_line_without_end_line(self):
        with self.assertRaises(ValueError) as ctx:
            main.read_file("proj", "a.txt", start_line="5", end_line=None)
        self.assertIn("必须是整数", str(ctx.exception))

    def test_rejects_float_start_line_without_end_line(self):
        with self.assertRaises(ValueError) as ctx:
            main.read_file("proj", "a.txt", start_line=1.5, end_line=None)
        self.assertIn("必须是整数", str(ctx.exception))

    def test_rejects_negative_start_line_without_end_line(self):
        with self.assertRaises(ValueError) as ctx:
            main.read_file("proj", "a.txt", start_line=-1, end_line=None)
        self.assertIn("必须 >= 1", str(ctx.exception))

    def test_rejects_bool_start_line_without_end_line(self):
        # bool 是 int 子类，必须在加法之前被拒绝
        with self.assertRaises(ValueError) as ctx:
            main.read_file("proj", "a.txt", start_line=True, end_line=None)
        self.assertIn("必须是整数", str(ctx.exception))

    def test_rejects_end_line_before_start_line(self):
        with self.assertRaises(ValueError) as ctx:
            main.read_file("proj", "a.txt", start_line=5, end_line=2)
        self.assertIn("行范围无效", str(ctx.exception))

    def test_accepts_legal_line_range(self):
        result = main.read_file("proj", "a.txt", start_line=1, end_line=2)
        self.assertEqual(result["status"], "ok")
        self.assertIn("line1", result["content"])


class ProjectIdTypeCheckTests(ChengxiangTestBase):
    """P2-4：解析器在集合查询前拒绝非字符串 project_id。"""

    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.make_file(self.project, "a.txt", b"hello\n")

    def test_rejects_list_project_id(self):
        with self.assertRaises(ValueError) as ctx:
            main.parse_tool_plan(
                plan_line("read_project", {}, project_id=[])
            )
        self.assertIn("project_id 必须是字符串", str(ctx.exception))

    def test_rejects_dict_project_id(self):
        with self.assertRaises(ValueError) as ctx:
            main.parse_tool_plan(
                plan_line("read_project", {}, project_id={"a": 1})
            )
        self.assertIn("project_id 必须是字符串", str(ctx.exception))

    def test_rejects_int_project_id(self):
        with self.assertRaises(ValueError) as ctx:
            main.parse_tool_plan(
                plan_line("read_project", {}, project_id=1)
            )
        self.assertIn("project_id 必须是字符串", str(ctx.exception))

    def test_accepts_registered_string_project_id(self):
        plan = main.parse_tool_plan(
            plan_line("read_project", {}, project_id="proj")
        )
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["project_id"], "proj")

    def test_rejects_unregistered_string_project_id(self):
        with self.assertRaises(PermissionError) as ctx:
            main.parse_tool_plan(
                plan_line("read_project", {}, project_id="unknown")
            )
        self.assertIn("项目未登记", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
