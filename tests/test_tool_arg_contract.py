"""D-5.15-A1：执行器参数键契约的独立防线。

覆盖 TOOL_ARG_SPEC / _check_arg_keys 在 execute_tool_plan 预检循环中的行为：
未知参数、缺少必需参数、合法参数、可选参数组合、非 dict 参数、
多工具计划的部分执行防护、审批消费语义。

【内部状态注入说明】
本文件通过直接伪造 main.PLAN_APPROVAL 抵达执行器预检循环，
等价于"绕过解析器、同进程代码直接构造计划"的内部能力，
**不是普通 CLI 用户可执行的路径**。
ChengxiangTestBase 会在每个用例后恢复授权全局。
"""

import unittest
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class ToolArgContractTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.make_file(self.project, "a.txt", b"hello\n")

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _forge(self, plan, permission="read"):
        main.PLAN_APPROVAL = {
            "fingerprint": main.tool_plan_fingerprint(plan),
            "permission": permission,
            "source": "human",
            "used": False,
        }
        main.AUTHORIZED_PERMISSION = permission
        main.STATE = "AUTHORIZED"

    def _item(self, name, args, project_id="proj"):
        return {"name": name, "project_id": project_id, "args": args}

    def _run_expecting_rejection(self, plan, permission="read"):
        self._forge(plan, permission)
        spies = {
            "read_project": mock.patch.object(main, "read_project"),
            "read_file": mock.patch.object(main, "read_file"),
            "search_project": mock.patch.object(main, "search_project"),
            "modify_file": mock.patch.object(main, "modify_file"),
        }
        started = {k: v.start() for k, v in spies.items()}
        try:
            with self.assertRaises(PermissionError) as ctx:
                main.execute_tool_plan(plan)
        finally:
            for patcher in spies.values():
                patcher.stop()

        for name, spy in started.items():
            spy.assert_not_called()
        return ctx.exception

    # ------------------------------------------------------------------
    # 1) 四个工具的合法参数放行
    # ------------------------------------------------------------------

    def test_legal_args_for_all_tools_are_allowed(self):
        cases = [
            ("read_project", {}, "read", "read_project"),
            ("read_file", {"relative_path": "a.txt"}, "read", "read_file"),
            ("search_project", {"keyword": "hello"}, "read", "search_project"),
            (
                "modify_file",
                {"relative_path": "a.txt", "old_text": "hello",
                 "new_text": "HELLO"},
                "modify",
                "modify_file",
            ),
        ]
        for name, args, permission, target in cases:
            with self.subTest(tool=name):
                plan = [self._item(name, args)]
                self._forge(plan, permission)
                with mock.patch.object(main, target) as spy:
                    main.execute_tool_plan(plan)
                self.assertEqual(spy.call_count, 1)

    # ------------------------------------------------------------------
    # 2) 四个工具的未知键均拒绝
    # ------------------------------------------------------------------

    def test_unknown_key_is_rejected_for_all_tools(self):
        cases = [
            ("read_project", {"x": 1}, "read"),
            ("read_file", {"relative_path": "a.txt", "x": 1}, "read"),
            ("search_project", {"keyword": "hello", "x": 1}, "read"),
            (
                "modify_file",
                {"relative_path": "a.txt", "old_text": "a",
                 "new_text": "b", "x": 1},
                "modify",
            ),
        ]
        for name, args, permission in cases:
            with self.subTest(tool=name):
                exc = self._run_expecting_rejection(
                    [self._item(name, args)], permission
                )
                self.assertIn("未经允许的参数", str(exc))

    # ------------------------------------------------------------------
    # 3) 缺少必需参数
    # ------------------------------------------------------------------

    def test_missing_required_args_are_rejected(self):
        cases = [
            ("read_file", {}),
            ("search_project", {}),
            (
                "modify_file",
                {"old_text": "a", "new_text": "b"},
            ),
            (
                "modify_file",
                {"relative_path": "a.txt", "new_text": "b"},
            ),
            (
                "modify_file",
                {"relative_path": "a.txt", "old_text": "a"},
            ),
        ]
        for name, args in cases:
            with self.subTest(tool=name, args=args):
                permission = "modify" if name == "modify_file" else "read"
                exc = self._run_expecting_rejection(
                    [self._item(name, args)], permission
                )
                self.assertIn("缺少必需参数", str(exc))

    # ------------------------------------------------------------------
    # 4) read_project 的空 args 放行
    # ------------------------------------------------------------------

    def test_read_project_accepts_empty_args(self):
        plan = [self._item("read_project", {})]
        self._forge(plan)
        with mock.patch.object(main, "read_project") as spy:
            main.execute_tool_plan(plan)
        spy.assert_called_once_with("proj")

    # ------------------------------------------------------------------
    # 5) read_file 的四种可选参数组合
    # ------------------------------------------------------------------

    def test_read_file_optional_combinations_are_allowed(self):
        combos = [
            {"relative_path": "a.txt"},
            {"relative_path": "a.txt", "start_line": 1},
            {"relative_path": "a.txt", "end_line": 2},
            {"relative_path": "a.txt", "start_line": 1, "end_line": 2},
        ]
        for args in combos:
            with self.subTest(args=args):
                plan = [self._item("read_file", args)]
                self._forge(plan)
                with mock.patch.object(main, "read_file") as spy:
                    main.execute_tool_plan(plan)
                self.assertEqual(spy.call_count, 1)

    # ------------------------------------------------------------------
    # 6) args 非 dict：保留现有拒绝行为
    # ------------------------------------------------------------------

    def test_non_dict_args_still_rejected(self):
        for bad in ([], "x", None):
            with self.subTest(args=bad):
                plan = [self._item("read_project", bad)]
                self._forge(plan)
                with self.assertRaises(PermissionError) as ctx:
                    main.execute_tool_plan(plan)
                self.assertIn("工具参数必须为对象", str(ctx.exception))

    # ------------------------------------------------------------------
    # 7) 缺必需参数 + 未知键同时出现
    # ------------------------------------------------------------------

    def test_missing_required_and_unknown_key_together(self):
        plan = [self._item("read_file", {"x": 1})]
        exc = self._run_expecting_rejection(plan)
        self.assertIn("未经允许的参数", str(exc))

    # ------------------------------------------------------------------
    # 8) 多工具计划：第一项合法、第二项参数错误
    # ------------------------------------------------------------------

    def test_multi_tool_plan_rejects_before_any_dispatch(self):
        plan = [
            self._item("read_project", {}),
            self._item("read_file", {}),          # 缺 relative_path
        ]
        exc = self._run_expecting_rejection(plan)
        self.assertIn("缺少必需参数", str(exc))

    # ------------------------------------------------------------------
    # 9) 预检失败后审批仍按现有设计消费
    # ------------------------------------------------------------------

    def test_approval_stays_consumed_after_precheck_failure(self):
        plan = [self._item("read_file", {})]
        self._run_expecting_rejection(plan)
        self.assertIs(main.PLAN_APPROVAL["used"], True)

    # ------------------------------------------------------------------
    # 10) 合法多工具计划无回归
    # ------------------------------------------------------------------

    def test_legal_multi_tool_plan_still_executes(self):
        plan = [
            self._item("read_project", {}),
            self._item("read_file", {"relative_path": "a.txt"}),
            self._item("search_project", {"keyword": "hello"}),
        ]
        self._forge(plan)
        with mock.patch.object(main, "read_project") as p1, \
                mock.patch.object(main, "read_file") as p2, \
                mock.patch.object(main, "search_project") as p3:
            results = main.execute_tool_plan(plan)

        self.assertEqual(len(results), 3)
        self.assertEqual(p1.call_count, 1)
        self.assertEqual(p2.call_count, 1)
        self.assertEqual(p3.call_count, 1)


if __name__ == "__main__":
    unittest.main()
