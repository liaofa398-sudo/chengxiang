"""F9：工具白名单——后续轮次只允许只读工具。"""

import inspect
import json
import unittest

import main
from tests.support import ChengxiangTestBase


def plan_line(tools):
    return "TOOL_PLAN_JSON: " + json.dumps({"tools": tools}, ensure_ascii=False)


class ToolWhitelistTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.make_file(self.project, "a.txt", b"hello\n")
        self.modify_plan = plan_line(
            [
                {
                    "name": "modify_file",
                    "project_id": "proj",
                    "args": {
                        "relative_path": "a.txt",
                        "old_text": "hello",
                        "new_text": "HELLO",
                    },
                }
            ]
        )

    def test_read_only_whitelist_rejects_modify_file(self):
        with self.assertRaises(PermissionError) as ctx:
            main.parse_tool_plan(
                self.modify_plan, allowed_tools=main.ALLOWED_READ_TOOLS
            )
        self.assertIn("仅允许只读工具", str(ctx.exception))

    def test_default_keeps_first_round_behaviour(self):
        plan = main.parse_tool_plan(self.modify_plan)
        self.assertEqual(plan[0]["name"], "modify_file")

    def test_read_only_whitelist_allows_read_tools(self):
        plan = main.parse_tool_plan(
            plan_line(
                [
                    {
                        "name": "search_project",
                        "project_id": "proj",
                        "args": {"keyword": "hello"},
                    }
                ]
            ),
            allowed_tools=main.ALLOWED_READ_TOOLS,
        )
        self.assertEqual(plan[0]["name"], "search_project")

    def test_unknown_tool_reports_unknown_not_disallowed(self):
        with self.assertRaises(PermissionError) as ctx:
            main.parse_tool_plan(
                plan_line(
                    [
                        {
                            "name": "delete_everything",
                            "project_id": "proj",
                            "args": {},
                        }
                    ]
                ),
                allowed_tools=main.ALLOWED_READ_TOOLS,
            )
        self.assertIn("未知工具", str(ctx.exception))

    def test_both_followup_call_sites_use_read_only_whitelist(self):
        source = inspect.getsource(main.main)
        self.assertEqual(
            source.count("allowed_tools=ALLOWED_READ_TOOLS"),
            2,
            "两个 follow-up 调用点都必须传只读白名单",
        )
        self.assertEqual(source.count("parse_tool_plan(content)"), 1)


if __name__ == "__main__":
    unittest.main()
