"""D-5.6：只读执行器边界与审批状态机入口的回归测试。

覆盖：
1. STATE 非 AUTHORIZED 时 execute_read_test 拒绝执行；
2. STATE=AUTHORIZED 且权限为 read 时，合法只读计划进入执行路径；
3. 含 modify_file 的计划被只读执行器拒绝，且修改工具未被调用；
4. approval_flow() 成功返回前已将状态置为 AUTHORIZED（即 main() 中不再需要重复赋值）。

隔离：复用 ChengxiangTestBase 的临时 HOME / BASE_DIR；
仅在测试 4 中 patch builtins.input 以驱动审批流程，不重构审批代码；
不访问网络、不执行 Git、不运行主程序、不触达真实修改。
"""

import json
import unittest
from unittest import mock

import main
from tests.support import ChengxiangTestBase


def plan_line(tools, project_id="proj"):
    payload = {"tools": tools}
    return "TOOL_PLAN_JSON: " + json.dumps(payload, ensure_ascii=False)


class ReadExecutorBoundaryTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.target = self.make_file(self.project, "a.txt", b"hello\n")

    # ------------------------------------------------------------------
    # 辅助：构造计划
    # ------------------------------------------------------------------

    def _read_plan(self):
        return main.parse_tool_plan(
            plan_line([
                {
                    "name": "read_file",
                    "project_id": "proj",
                    "args": {"relative_path": "a.txt"},
                }
            ])
        )

    def _modify_plan(self):
        return main.parse_tool_plan(
            plan_line([
                {
                    "name": "modify_file",
                    "project_id": "proj",
                    "args": {
                        "relative_path": "a.txt",
                        "old_text": "hello",
                        "new_text": "HELLO",
                    },
                }
            ])
        )

    # ------------------------------------------------------------------
    # 1) STATE 非 AUTHORIZED
    # ------------------------------------------------------------------

    def test_rejects_when_state_is_not_authorized(self):
        plan = self._read_plan()
        main.STATE = "IDLE"

        with self.assertRaises(PermissionError) as ctx:
            main.execute_read_test(plan)

        self.assertIn("当前不是 AUTHORIZED 状态", str(ctx.exception))
        self.assertEqual(self.target.read_bytes(), b"hello\n")

    # ------------------------------------------------------------------
    # 2) 合法只读计划进入执行路径
    # ------------------------------------------------------------------

    def test_authorized_read_plan_enters_execution_path(self):
        plan = self._read_plan()
        main.AUTHORIZED_PERMISSION = "read"
        main.STATE = "AUTHORIZED"
        main.bind_plan_approval(plan, "read", "human")

        sentinel_result = [{"tool": "read_file", "status": "success"}]

        with mock.patch.object(
            main, "execute_tool_plan", return_value=sentinel_result
        ) as spy:
            results = main.execute_read_test(plan)

        spy.assert_called_once_with(plan)
        self.assertEqual(results, sentinel_result)
        # finally 已收回授权并复位状态
        self.assertIsNone(main.AUTHORIZED_PERMISSION)
        self.assertEqual(main.STATE, "IDLE")

    # ------------------------------------------------------------------
    # 3) 只读执行器拒绝 modify_file
    # ------------------------------------------------------------------

    def test_rejects_modify_tool_before_dispatch(self):
        plan = self._modify_plan()
        main.AUTHORIZED_PERMISSION = "read"
        main.STATE = "AUTHORIZED"

        with mock.patch.object(main, "execute_tool_plan") as plan_spy, \
                mock.patch.object(main, "modify_file") as modify_spy:
            with self.assertRaises(PermissionError) as ctx:
                main.execute_read_test(plan)

        self.assertIn("只读执行器拒绝非只读工具", str(ctx.exception))
        plan_spy.assert_not_called()
        modify_spy.assert_not_called()
        self.assertEqual(self.target.read_bytes(), b"hello\n")
        self.assertEqual(self.backups(self.project), [])
        self.assertEqual(self.partials(self.project), [])

    # ------------------------------------------------------------------
    # 4) approval_flow() 成功返回前即已置为 AUTHORIZED
    # ------------------------------------------------------------------

    def test_approval_success_establishes_authorized_state(self):
        plan = self._read_plan()
        main.CURRENT_TOOL_PLAN = plan
        main.STATE = "IDLE"
        main.AUTHORIZED_PERMISSION = None

        with mock.patch("builtins.input", return_value="准奏 read"):
            permission = main.approval_flow()

        self.assertEqual(permission, "read")
        # 这正是 main() 中不再需要重复写 STATE 的依据
        self.assertEqual(main.STATE, "AUTHORIZED")
        self.assertEqual(main.AUTHORIZED_PERMISSION, "read")
        self.assertIsNotNone(main.PLAN_APPROVAL)
        self.assertIs(main.PLAN_APPROVAL["used"], False)
        self.assertEqual(main.PLAN_APPROVAL["permission"], "read")


if __name__ == "__main__":
    unittest.main()
