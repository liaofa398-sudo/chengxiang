"""D-5.17-A3 O-2：approval_flow() 分支的自动化覆盖。

通过 mock.patch("builtins.input") 驱动各分支，不重构生产代码。
每个用例由 ChengxiangTestBase 提供独立临时 HOME / BASE_DIR，
并在结束后恢复 STATE / AUTHORIZED_PERMISSION / PLAN_APPROVAL 等全局。
"""

import io
import json
import unittest
from contextlib import redirect_stdout
from unittest import mock

import main
from tests.support import ChengxiangTestBase


def plan_line(tool, args, project_id="proj"):
    payload = {"tools": [{"name": tool, "project_id": project_id, "args": args}]}
    return "TOOL_PLAN_JSON: " + json.dumps(payload, ensure_ascii=False)


class ApprovalFlowBranchTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.make_file(self.project, "a.txt", b"hello\n")

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _read_plan(self):
        return main.parse_tool_plan(
            plan_line("read_project", {})
        )

    def _modify_plan(self):
        return main.parse_tool_plan(
            plan_line(
                "modify_file",
                {
                    "relative_path": "a.txt",
                    "old_text": "hello",
                    "new_text": "HELLO",
                },
            )
        )

    def _run(self, answer):
        with mock.patch("builtins.input", return_value=answer), \
                redirect_stdout(io.StringIO()):
            return main.approval_flow()

    def assertNoAuthorization(self):
        self.assertIsNone(main.AUTHORIZED_PERMISSION)
        self.assertIsNone(main.PLAN_APPROVAL)

    # ------------------------------------------------------------------
    # 1) 驳回
    # ------------------------------------------------------------------

    def test_reject_clears_authorization(self):
        self._read_plan()
        self.assertEqual(self._run("驳回"), None)
        self.assertNoAuthorization()
        self.assertEqual(main.STATE, "IDLE")

    # ------------------------------------------------------------------
    # 2) 退出
    # ------------------------------------------------------------------

    def test_exit_sets_exit_state(self):
        self._read_plan()
        self.assertEqual(self._run("退出"), "退出")
        self.assertNoAuthorization()
        self.assertEqual(main.STATE, "EXIT")

    # ------------------------------------------------------------------
    # 3) 无效权限
    # ------------------------------------------------------------------

    def test_invalid_permission_grants_nothing(self):
        self._read_plan()
        self.assertEqual(self._run("准奏 bogus"), None)
        self.assertNoAuthorization()
        self.assertEqual(main.STATE, "IDLE")

    # ------------------------------------------------------------------
    # 4) 格式错误
    # ------------------------------------------------------------------

    def test_malformed_approval_grants_nothing(self):
        self._read_plan()
        self.assertEqual(self._run("准奏"), None)
        self.assertNoAuthorization()
        self.assertEqual(main.STATE, "IDLE")

    # ------------------------------------------------------------------
    # 5) 无有效计划
    # ------------------------------------------------------------------

    def test_empty_plan_grants_nothing(self):
        main.CURRENT_TOOL_PLAN = []
        self.assertEqual(self._run("准奏 read"), None)
        self.assertNoAuthorization()
        self.assertEqual(main.STATE, "IDLE")

    # ------------------------------------------------------------------
    # 6) 绑定失败（权限与计划不匹配）
    # ------------------------------------------------------------------

    def test_bind_failure_clears_authorization(self):
        self._modify_plan()          # 需要 modify
        self.assertEqual(self._run("准奏 read"), None)
        self.assertNoAuthorization()
        self.assertEqual(main.STATE, "IDLE")

    # ------------------------------------------------------------------
    # 7) 审批审计失败
    # ------------------------------------------------------------------

    def test_audit_failure_clears_authorization(self):
        self._read_plan()
        real_audit = main.audit_event

        def failing(event, **fields):
            if event == "approval_bound":
                raise OSError("audit boom")
            return real_audit(event, **fields)

        with mock.patch.object(main, "audit_event", side_effect=failing):
            self.assertEqual(self._run("准奏 read"), None)

        self.assertNoAuthorization()
        self.assertEqual(main.STATE, "IDLE")

    # ------------------------------------------------------------------
    # 8) 正常批准
    # ------------------------------------------------------------------

    def test_successful_approval_binds(self):
        self._read_plan()
        self.assertEqual(self._run("准奏 read"), "read")
        self.assertEqual(main.AUTHORIZED_PERMISSION, "read")
        self.assertEqual(main.STATE, "AUTHORIZED")
        self.assertIsNotNone(main.PLAN_APPROVAL)
        self.assertIs(main.PLAN_APPROVAL["used"], False)
        self.assertEqual(main.PLAN_APPROVAL["permission"], "read")

    # ------------------------------------------------------------------
    # 9) 执行异常后的清理（复现真实调用方逻辑）
    # ------------------------------------------------------------------

    def test_execution_failure_then_cleanup(self):
        plan = self._modify_plan()
        self.assertEqual(self._run("准奏 modify"), "modify")

        def boom(*args, **kwargs):
            raise OSError("tool boom")

        with mock.patch.object(main, "modify_file", side_effect=boom):
            with self.assertRaises(main.ToolPlanExecutionError):
                main.execute_tool_plan(plan)

        # 审批已消费，不可重放
        self.assertIs(main.PLAN_APPROVAL["used"], True)
        with self.assertRaises(PermissionError):
            main.execute_tool_plan(plan)

        # 调用方（main）的清理逻辑
        main.clear_authorization()
        main.CURRENT_TOOL_PLAN = []
        main.STATE = "IDLE"

        self.assertNoAuthorization()
        self.assertEqual(main.STATE, "IDLE")
        self.assertEqual((self.project / "a.txt").read_bytes(), b"hello\n")


class ApprovalWiringTests(ChengxiangTestBase):
    """守卫：两个调用点必须各司其职。

    审批分支应把用户已输入的「准奏 xxx」透传给 approval_flow(command)，
    避免二次询问；正常任务流必须调用 approval_flow() 让皇帝当场裁决。
    若两者写反，会出现「圣裁无效」或「重复询问」。
    """

    def test_call_sites_are_wired_correctly(self):
        from pathlib import Path

        src = Path(main.__file__).read_text(encoding="utf-8")
        self.assertEqual(
            src.count("permission = approval_flow(command)"), 1
        )
        self.assertEqual(src.count("permission = approval_flow()"), 1)


if __name__ == "__main__":
    unittest.main()
