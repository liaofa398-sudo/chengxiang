"""D-5.2：中央授权层与审批生命周期的防御性测试。

覆盖：
A. permission_level 的已知映射与未知权限拒绝；
B. require_permission 的四类拒绝与一条正向对照；
C. execute_tool_plan 的三种状态拒绝（并核对审批消耗时机）；
D. 绑定后篡改计划导致的指纹失配拒绝。

隔离：全部使用 ChengxiangTestBase 的临时 HOME / BASE_DIR，
不调用 call_deepseek()、approval_flow()，不访问网络，不执行 Git，
所有被拒绝的路径都发生在工具分发之前，因此不会触碰真实文件。
"""

import json
import unittest
from unittest import mock

import main
from tests.support import ChengxiangTestBase


def plan_line(tool, args, project_id="proj"):
    payload = {
        "tools": [
            {"name": tool, "project_id": project_id, "args": args}
        ]
    }
    return "TOOL_PLAN_JSON: " + json.dumps(payload, ensure_ascii=False)


class _AuditAssertions:
    """拒绝路径不得产生新的审计记录。"""

    def _audit_lines(self):
        if not main.AUDIT_FILE.exists():
            return []
        return main.AUDIT_FILE.read_text(encoding="utf-8").splitlines()

    def assertNoNewAuditRecords(self, before):
        self.assertEqual(
            self._audit_lines(), before,
            "拒绝路径不得写入新的审计记录",
        )


# ----------------------------------------------------------------------
# A. permission_level
# ----------------------------------------------------------------------

class PermissionLevelTests(ChengxiangTestBase):
    def test_known_permissions_map_to_expected_levels(self):
        self.assertEqual(main.permission_level("read"), 1)
        self.assertEqual(main.permission_level("modify"), 2)
        self.assertEqual(main.permission_level("git"), 3)
        self.assertEqual(main.permission_level("dangerous"), 4)

    def test_unknown_permission_is_rejected(self):
        for bogus in ("bogus", "", "READ", " modif", None, 0):
            with self.subTest(permission=bogus):
                with self.assertRaises(ValueError) as ctx:
                    main.permission_level(bogus)
                self.assertIn("拒绝未知权限", str(ctx.exception))

    def test_unknown_permission_is_not_treated_as_valid(self):
        self.assertNotIn("bogus", main.PERMISSIONS)


# ----------------------------------------------------------------------
# B. require_permission
# ----------------------------------------------------------------------

class RequirePermissionTests(ChengxiangTestBase):
    def test_denies_when_no_authorization(self):
        main.AUTHORIZED_PERMISSION = None
        with self.assertRaises(PermissionError) as ctx:
            main.require_permission("read")
        self.assertIn("未获授权", str(ctx.exception))

    def test_denies_unknown_current_permission(self):
        main.AUTHORIZED_PERMISSION = "bogus"
        with self.assertRaises(PermissionError) as ctx:
            main.require_permission("read")
        self.assertIn("拒绝未知权限", str(ctx.exception))

    def test_denies_unknown_target_permission(self):
        main.AUTHORIZED_PERMISSION = "modify"
        with self.assertRaises(PermissionError) as ctx:
            main.require_permission("bogus")
        self.assertIn("拒绝未知的目标权限", str(ctx.exception))

    def test_denies_insufficient_level(self):
        main.AUTHORIZED_PERMISSION = "read"
        with self.assertRaises(PermissionError) as ctx:
            main.require_permission("modify")
        self.assertIn("权限不足", str(ctx.exception))

    def test_allows_sufficient_level(self):
        main.AUTHORIZED_PERMISSION = "modify"
        main.require_permission("read")
        main.require_permission("modify")


# ----------------------------------------------------------------------
# C. execute_tool_plan 状态检查
# ----------------------------------------------------------------------

class ExecutionStateTests(_AuditAssertions, ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.target = self.make_file(self.project, "a.txt", b"hello\n")

    def _bound_plan(self):
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

    def assertNoToolSideEffects(self):
        self.assertEqual(self.target.read_bytes(), b"hello\n",
                         "目标文件不得被修改")
        self.assertEqual(self.backups(self.project), [], "不得产生 .bak")
        self.assertEqual(self.partials(self.project), [], "不得产生 .partial")

    def test_execute_requires_authorized_state(self):
        plan = self._bound_plan()
        main.STATE = "IDLE"
        audit_before = self._audit_lines()

        with mock.patch.object(main, "modify_file") as spy:
            with self.assertRaises(PermissionError) as ctx:
                main.execute_tool_plan(plan)

        self.assertIn("未进入 AUTHORIZED 状态", str(ctx.exception))
        spy.assert_not_called()
        # 状态检查早于审批消耗，used 必须仍为 False
        self.assertIs(main.PLAN_APPROVAL["used"], False)
        self.assertNoToolSideEffects()
        self.assertNoNewAuditRecords(audit_before)

    def test_execute_requires_approval_record(self):
        plan = self._bound_plan()
        main.PLAN_APPROVAL = None
        audit_before = self._audit_lines()

        with mock.patch.object(main, "modify_file") as spy:
            with self.assertRaises(PermissionError) as ctx:
                main.execute_tool_plan(plan)

        self.assertIn("没有有效的、未使用的计划批准记录", str(ctx.exception))
        spy.assert_not_called()
        self.assertIsNone(main.PLAN_APPROVAL)
        self.assertNoToolSideEffects()
        self.assertNoNewAuditRecords(audit_before)

    def test_execute_rejects_used_approval(self):
        plan = self._bound_plan()
        main.PLAN_APPROVAL["used"] = True
        audit_before = self._audit_lines()

        with mock.patch.object(main, "modify_file") as spy:
            with self.assertRaises(PermissionError) as ctx:
                main.execute_tool_plan(plan)

        self.assertIn("没有有效的、未使用的计划批准记录", str(ctx.exception))
        spy.assert_not_called()
        self.assertIs(main.PLAN_APPROVAL["used"], True)
        self.assertNoToolSideEffects()
        self.assertNoNewAuditRecords(audit_before)


# ----------------------------------------------------------------------
# D. 审批后篡改计划
# ----------------------------------------------------------------------

class PlanTamperTests(_AuditAssertions, ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.target = self.make_file(self.project, "a.txt", b"hello\n")

    def _bound_plan(self):
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

    def test_tampered_plan_is_rejected_by_fingerprint(self):
        plan = self._bound_plan()
        bound_fingerprint = main.PLAN_APPROVAL["fingerprint"]
        audit_before = self._audit_lines()

        plan[0]["args"]["new_text"] = "TAMPERED"

        # 先证明篡改确实改变了指纹
        self.assertNotEqual(
            main.tool_plan_fingerprint(plan), bound_fingerprint,
            "篡改后指纹必须变化",
        )

        with mock.patch.object(main, "modify_file") as spy:
            with self.assertRaises(PermissionError) as ctx:
                main.execute_tool_plan(plan)

        message = str(ctx.exception)
        # 确认拒绝来自指纹校验，而不是其它前置检查
        self.assertIn("计划与获批内容不一致", message)
        self.assertNotIn("未进入 AUTHORIZED 状态", message)
        self.assertNotIn("没有有效的、未使用的计划批准记录", message)
        self.assertNotIn("当前权限与批准记录不一致", message)

        spy.assert_not_called()
        # 指纹校验晚于审批消耗：used 必须已为 True
        self.assertIs(main.PLAN_APPROVAL["used"], True)
        # 授权本身不由 execute_tool_plan 清除
        self.assertEqual(main.AUTHORIZED_PERMISSION, "modify")
        self.assertEqual(
            main.PLAN_APPROVAL["fingerprint"], bound_fingerprint,
            "拒绝不得改写已绑定的指纹",
        )
        # 目标文件未变、无备份、无临时文件
        self.assertEqual(self.target.read_bytes(), b"hello\n")
        self.assertEqual(self.backups(self.project), [])
        self.assertEqual(self.partials(self.project), [])
        self.assertNoNewAuditRecords(audit_before)


if __name__ == "__main__":
    unittest.main()
