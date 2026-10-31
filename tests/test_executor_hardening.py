"""D-5.12-A：执行器防御纵深（P-1 / P-2 / P-4 / 审计包装）。

覆盖：
1. bind 阶段拒绝非字符串 name；
2. executor 阶段拒绝非字符串 name；
3. executor 阶段拒绝非字符串 project_id；
4. 20 项计划允许通过；
5. 21 项计划被拒绝；
6. execution_started 审计失败后抛 RuntimeError；
7. 审计失败时工具未被调用；
8. 审计异常链保留原始异常；
9. 正常字符串 name / project_id 不受影响。

【内部状态注入说明】
用例 2、3 通过直接伪造 main.PLAN_APPROVAL 抵达执行器的 name / project_id
检查点。这等价于"同进程代码可改写模块全局"的内部能力，**不是普通 CLI
用户可执行的路径**。夹具 ChengxiangTestBase 会在每个用例后恢复
STATE / AUTHORIZED_PERMISSION / PLAN_APPROVAL，不会留下污染。
"""

import errno
import unittest
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class ExecutorHardeningTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.make_file(self.project, "a.txt", b"hello\n")

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _read_plan(self, count=1):
        return [
            {"name": "read_project", "project_id": "proj", "args": {}}
            for _ in range(count)
        ]

    def _forge_approval(self, plan, permission="read"):
        """内部状态注入：伪造一份与该计划指纹匹配的审批记录。"""
        main.PLAN_APPROVAL = {
            "fingerprint": main.tool_plan_fingerprint(plan),
            "permission": permission,
            "source": "human",
            "used": False,
        }
        main.AUTHORIZED_PERMISSION = permission
        main.STATE = "AUTHORIZED"

    def _bind(self, plan, permission="read"):
        main.bind_plan_approval(plan, permission, "human")
        main.AUTHORIZED_PERMISSION = permission
        main.STATE = "AUTHORIZED"

    # ------------------------------------------------------------------
    # 1) bind 阶段拒绝非字符串 name
    # ------------------------------------------------------------------

    def test_bind_rejects_non_string_name(self):
        plan = [{"name": ["read_project"], "project_id": "proj", "args": {}}]

        with self.assertRaises(PermissionError) as ctx:
            main.bind_plan_approval(plan, "read", "human")

        self.assertIn("工具名称类型不合法", str(ctx.exception))

    # ------------------------------------------------------------------
    # 2) executor 阶段拒绝非字符串 name（内部状态注入）
    # ------------------------------------------------------------------

    def test_executor_rejects_non_string_name_via_forged_approval(self):
        plan = [{"name": ["read_project"], "project_id": "proj", "args": {}}]
        self._forge_approval(plan)

        with mock.patch.object(main, "read_project") as spy:
            with self.assertRaises(PermissionError) as ctx:
                main.execute_tool_plan(plan)

        self.assertIn("工具名称类型不合法", str(ctx.exception))
        spy.assert_not_called()
        self.assertIs(main.PLAN_APPROVAL["used"], True)

    # ------------------------------------------------------------------
    # 3) executor 阶段拒绝非字符串 project_id（内部状态注入）
    # ------------------------------------------------------------------

    def test_executor_rejects_non_string_project_id_via_forged_approval(self):
        plan = [{"name": "read_project", "project_id": [], "args": {}}]
        self._forge_approval(plan)

        with mock.patch.object(main, "read_project") as spy:
            with self.assertRaises(PermissionError) as ctx:
                main.execute_tool_plan(plan)

        self.assertIn("project_id 类型不合法", str(ctx.exception))
        spy.assert_not_called()

    # ------------------------------------------------------------------
    # 4) 20 项允许通过
    # ------------------------------------------------------------------

    def test_twenty_tools_is_allowed(self):
        plan = self._read_plan(20)
        self._bind(plan)

        with mock.patch.object(
            main, "read_project", return_value={"ok": True}
        ) as spy:
            results = main.execute_tool_plan(plan)

        self.assertEqual(len(results), 20)
        self.assertEqual(spy.call_count, 20)

    # ------------------------------------------------------------------
    # 5) 21 项被拒绝
    # ------------------------------------------------------------------

    def test_twenty_one_tools_is_rejected(self):
        plan = self._read_plan(21)
        self._bind(plan)

        with mock.patch.object(main, "read_project") as spy:
            with self.assertRaises(PermissionError) as ctx:
                main.execute_tool_plan(plan)

        self.assertIn("超过 20 个", str(ctx.exception))
        spy.assert_not_called()
        self.assertIs(main.PLAN_APPROVAL["used"], True)

    # ------------------------------------------------------------------
    # 6~8) execution_started 审计失败
    # ------------------------------------------------------------------

    def _install_failing_audit(self):
        real_audit = main.audit_event

        def failing(event, **fields):
            if event == "execution_started":
                raise OSError(errno.EIO, "audit boom")
            return real_audit(event, **fields)

        return failing

    def test_audit_failure_raises_runtime_error(self):
        plan = self._read_plan(1)
        self._bind(plan)

        with mock.patch.object(
            main, "audit_event", side_effect=self._install_failing_audit()
        ):
            with self.assertRaises(RuntimeError) as ctx:
                main.execute_tool_plan(plan)

        self.assertIn("执行前审计写入失败", str(ctx.exception))
        self.assertNotIsInstance(ctx.exception, main.ToolPlanExecutionError)
        self.assertIs(main.PLAN_APPROVAL["used"], True)

    def test_audit_failure_prevents_tool_dispatch(self):
        plan = self._read_plan(1)
        self._bind(plan)

        with mock.patch.object(
            main, "audit_event", side_effect=self._install_failing_audit()
        ), mock.patch.object(main, "read_project") as spy:
            with self.assertRaises(RuntimeError):
                main.execute_tool_plan(plan)

        spy.assert_not_called()

    def test_audit_failure_keeps_exception_chain(self):
        plan = self._read_plan(1)
        self._bind(plan)

        with mock.patch.object(
            main, "audit_event", side_effect=self._install_failing_audit()
        ):
            with self.assertRaises(RuntimeError) as ctx:
                main.execute_tool_plan(plan)

        cause = ctx.exception.__cause__
        self.assertIsInstance(cause, OSError)
        self.assertIn("audit boom", str(cause))

    # ------------------------------------------------------------------
    # 9) 正常字符串 name / project_id 不受影响
    # ------------------------------------------------------------------

    def test_normal_name_and_project_id_still_work(self):
        plan = self._read_plan(1)
        self._bind(plan)

        with mock.patch.object(
            main, "read_project", return_value={"ok": True}
        ) as spy:
            results = main.execute_tool_plan(plan)

        self.assertEqual(len(results), 1)
        spy.assert_called_once_with("proj")


if __name__ == "__main__":
    unittest.main()
