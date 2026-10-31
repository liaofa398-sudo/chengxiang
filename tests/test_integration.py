"""端到端：审批绑定 → 计划执行 → 审计落盘。

验证新的 modify_file 与 execute_tool_plan 的接线仍然正确。
"""

import json
import stat
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


class ExecutionIntegrationTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.target = self.make_file(self.project, "a.txt", b"hello\n")

    def _approved_modify_plan(self):
        plan = main.parse_tool_plan(
            plan_line(
                "modify_file",
                {
                    "relative_path": "a.txt",
                    "old_text": "hello",
                    "new_text": "HELLO",
                },
            )
        )
        main.bind_plan_approval(plan, "modify", "human")
        main.AUTHORIZED_PERMISSION = "modify"
        main.STATE = "AUTHORIZED"
        return plan

    def test_execute_modify_plan_end_to_end(self):
        plan = self._approved_modify_plan()
        results = main.execute_tool_plan(plan)

        self.assertEqual(self.target.read_bytes(), b"HELLO\n")
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["result"]["backup"])

        audit = main.AUDIT_FILE.read_text(encoding="utf-8").splitlines()
        events = [json.loads(line)["event"] for line in audit]
        self.assertIn("execution_started", events)
        self.assertIn("tool_succeeded", events)
        self.assertIn("execution_finished", events)

    def test_audit_file_mode_is_600(self):
        self._approved_modify_plan()
        main.execute_tool_plan(main.CURRENT_TOOL_PLAN)
        mode = stat.S_IMODE(main.AUDIT_FILE.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_plan_approval_cannot_be_reused(self):
        plan = self._approved_modify_plan()
        main.execute_tool_plan(plan)
        with self.assertRaises(PermissionError):
            main.execute_tool_plan(plan)

    def test_read_approval_cannot_cover_modify_plan(self):
        plan = main.parse_tool_plan(
            plan_line(
                "modify_file",
                {
                    "relative_path": "a.txt",
                    "old_text": "hello",
                    "new_text": "HELLO",
                },
            )
        )
        with self.assertRaises(PermissionError):
            main.bind_plan_approval(plan, "read", "human")
        self.assertEqual(self.target.read_bytes(), b"hello\n")

    def test_failure_stops_and_reports_remaining(self):
        plan = self._approved_modify_plan()
        plan.append(
            {
                "name": "read_file",
                "project_id": "proj",
                "args": {
                    "relative_path": "missing.txt",
                },
            }
        )
        main.bind_plan_approval(plan, "modify", "human")

        with self.assertRaises(main.ToolPlanExecutionError) as ctx:
            main.execute_tool_plan(plan)

        report = ctx.exception.report
        self.assertEqual(report[0]["status"], "success")
        self.assertEqual(report[1]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
