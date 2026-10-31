"""D-5.17-A0-F1：单份计划最多允许 1 个修改操作。

覆盖：
1. 0 个修改（纯只读）可绑定；
2. 1 个修改可绑定；
3. 2 个修改在绑定阶段被拒绝；
4. 2 个修改 + 伪造审批直调 executor 也被拒绝（consumed 且不可重放）；
5. 1 读 + 1 修改（混合）可绑定，权限取最高；
6. 未知工具仍优先于"修改操作过多"报错；
7. 20 个只读操作仍允许（不误伤只读批量）。

【内部状态注入说明】
用例 4 通过直接伪造 main.PLAN_APPROVAL 抵达 executor，
等价于"同进程代码绕过 bind_plan_approval"的内部能力，
**不是普通 CLI 用户可执行的路径**。
"""

import unittest
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class ModifyOpLimitTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.make_file(self.project, "a.txt", b"hello\n")
        self.make_file(self.project, "b.txt", b"world\n")

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _item(self, name, args, project_id="proj"):
        return {"name": name, "project_id": project_id, "args": args}

    def _modify(self, rel, old, new):
        return self._item(
            "modify_file",
            {"relative_path": rel, "old_text": old, "new_text": new},
        )

    def _read_project(self):
        return self._item("read_project", {})

    def _two_modifies(self):
        return [
            self._modify("a.txt", "hello", "HELLO"),
            self._modify("b.txt", "world", "WORLD"),
        ]

    # ------------------------------------------------------------------
    # 1) 0 个修改
    # ------------------------------------------------------------------

    def test_zero_modify_plan_binds_with_read(self):
        plan = [self._read_project()]
        main.bind_plan_approval(plan, "read", "human")
        self.assertIsNotNone(main.PLAN_APPROVAL)
        self.assertIs(main.PLAN_APPROVAL["used"], False)

    # ------------------------------------------------------------------
    # 2) 1 个修改
    # ------------------------------------------------------------------

    def test_single_modify_plan_binds(self):
        plan = [self._modify("a.txt", "hello", "HELLO")]
        main.bind_plan_approval(plan, "modify", "human")
        self.assertIs(main.PLAN_APPROVAL["used"], False)

    # ------------------------------------------------------------------
    # 3) 2 个修改：绑定阶段拒绝
    # ------------------------------------------------------------------

    def test_two_modify_ops_rejected_at_bind(self):
        with self.assertRaises(PermissionError) as ctx:
            main.bind_plan_approval(self._two_modifies(), "modify", "human")

        self.assertIn("最多允许", str(ctx.exception))
        self.assertIsNone(main.PLAN_APPROVAL)

    # ------------------------------------------------------------------
    # 4) 2 个修改：伪造审批直调 executor
    # ------------------------------------------------------------------

    def test_two_modify_ops_rejected_at_executor_via_forged_approval(self):
        plan = self._two_modifies()
        main.PLAN_APPROVAL = {
            "fingerprint": main.tool_plan_fingerprint(plan),
            "permission": "modify",
            "source": "human",
            "used": False,
        }
        main.AUTHORIZED_PERMISSION = "modify"
        main.STATE = "AUTHORIZED"

        with mock.patch.object(main, "modify_file") as spy:
            with self.assertRaises(PermissionError) as ctx:
                main.execute_tool_plan(plan)

        self.assertIn("最多允许", str(ctx.exception))
        spy.assert_not_called()
        # 审批已消费
        self.assertIs(main.PLAN_APPROVAL["used"], True)

        # 不可重放
        with mock.patch.object(main, "modify_file") as spy2:
            with self.assertRaises(PermissionError) as ctx2:
                main.execute_tool_plan(plan)
        self.assertIn("没有有效的、未使用的计划批准记录", str(ctx2.exception))
        spy2.assert_not_called()

        # 目标文件未被修改
        self.assertEqual((self.project / "a.txt").read_bytes(), b"hello\n")
        self.assertEqual((self.project / "b.txt").read_bytes(), b"world\n")

    # ------------------------------------------------------------------
    # 5) 1 读 + 1 修改
    # ------------------------------------------------------------------

    def test_read_and_modify_mixed_plan_binds_with_modify(self):
        plan = [
            self._read_project(),
            self._modify("a.txt", "hello", "HELLO"),
        ]
        main.bind_plan_approval(plan, "modify", "human")
        self.assertEqual(main.PLAN_APPROVAL["permission"], "modify")

        # 用 read 权限绑定同一计划必须失败（权限取最高）
        main.PLAN_APPROVAL = None
        with self.assertRaises(PermissionError):
            main.bind_plan_approval(plan, "read", "human")

    # ------------------------------------------------------------------
    # 6) 未知工具优先级
    # ------------------------------------------------------------------

    def test_unknown_tool_still_wins_over_modify_limit(self):
        plan = self._two_modifies() + [self._item("delete_all", {})]
        with self.assertRaises(PermissionError) as ctx:
            main.bind_plan_approval(plan, "modify", "human")
        self.assertIn("未知工具", str(ctx.exception))

    # ------------------------------------------------------------------
    # 7) 20 个只读操作仍允许
    # ------------------------------------------------------------------

    def test_twenty_read_ops_still_allowed(self):
        plan = [self._read_project() for _ in range(20)]
        main.bind_plan_approval(plan, "read", "human")
        self.assertIsNotNone(main.PLAN_APPROVAL)


if __name__ == "__main__":
    unittest.main()
