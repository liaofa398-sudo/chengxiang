"""D-5.8：parse_tool_plan 的解析器类型加固。

覆盖 D-5.7 确认的 P-1 ~ P-4：
P-1 顶层 JSON 必须是对象；
P-2 args 类型检查前移（不得由 .keys() 触发 AttributeError）；
P-3 name 必须是字符串（不得由集合成员判断触发 TypeError）；
P-4 search_project 的 keyword 类型/长度校验（解析期 + 入口期，且早于目录遍历）。

所有用例直接调用 parse_tool_plan / search_project，
因此断言的是"错误在该阶段发生"，而不是被上层兜底包装。
"""

import json
import unittest
from pathlib import Path
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class PlanParserHardeningTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.make_file(self.project, "a.txt", b"hello\n")

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _content(self, payload):
        return "TOOL_PLAN_JSON: " + payload

    def _plan_json(self, tools):
        return self._content(json.dumps({"tools": tools}, ensure_ascii=False))

    def _item(self, name, args, project_id="proj"):
        item = {"name": name, "project_id": project_id}
        if args is not ...:
            item["args"] = args
        return item

    # ------------------------------------------------------------------
    # P-1 顶层 JSON 类型
    # ------------------------------------------------------------------

    def test_top_level_non_dict_is_rejected(self):
        for raw in ("[]", '"abc"', "123", "null", "true"):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError) as ctx:
                    main.parse_tool_plan(self._content(raw))
                self.assertIn("顶层必须是 JSON 对象", str(ctx.exception))

    # ------------------------------------------------------------------
    # P-2 args 类型检查前移
    # ------------------------------------------------------------------

    def test_args_non_dict_is_rejected_for_all_tools(self):
        for tool in ("read_project", "read_file", "search_project",
                     "modify_file"):
            for bad in ([], "x", None):
                with self.subTest(tool=tool, args=bad):
                    content = self._plan_json([self._item(tool, bad)])
                    with self.assertRaises(ValueError) as ctx:
                        main.parse_tool_plan(content)
                    self.assertIn("args 必须是 JSON 对象", str(ctx.exception))

    def test_modify_file_bad_args_does_not_raise_attribute_error(self):
        # 修复前这里会因 args.keys() 抛 AttributeError
        content = self._plan_json([self._item("modify_file", [])])
        with self.assertRaises(ValueError):
            main.parse_tool_plan(content)

    def test_missing_args_still_defaults_to_empty_dict(self):
        # read_project 不传 args 时必须保持可解析（接口语义不变）
        content = self._plan_json([self._item("read_project", ...)])
        plan = main.parse_tool_plan(content)
        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["args"], {})

    def test_explicit_null_args_is_rejected(self):
        # 显式 null 与"缺省"不同：现有语义为拒绝，本轮保持不变
        content = self._plan_json([self._item("read_project", None)])
        with self.assertRaises(ValueError):
            main.parse_tool_plan(content)

    # ------------------------------------------------------------------
    # P-3 name 类型
    # ------------------------------------------------------------------

    def test_name_non_string_is_rejected(self):
        for bad in (["read_file"], {"a": 1}, None, 123):
            with self.subTest(name=bad):
                content = self._plan_json([
                    {"name": bad, "project_id": "proj", "args": {}}
                ])
                with self.assertRaises(ValueError) as ctx:
                    main.parse_tool_plan(content)
                self.assertIn("name 必须是字符串", str(ctx.exception))

    # ------------------------------------------------------------------
    # P-4 keyword 加固
    # ------------------------------------------------------------------

    def test_keyword_type_is_rejected(self):
        for bad in (123, [], None):
            with self.subTest(keyword=bad):
                content = self._plan_json([
                    self._item("search_project", {"keyword": bad})
                ])
                with self.assertRaises(ValueError):
                    main.parse_tool_plan(content)

    def test_keyword_empty_is_rejected(self):
        content = self._plan_json([
            self._item("search_project", {"keyword": ""})
        ])
        with self.assertRaises(ValueError) as ctx:
            main.parse_tool_plan(content)
        self.assertIn("不能为空", str(ctx.exception))

    def test_keyword_too_long_is_rejected(self):
        content = self._plan_json([
            self._item("search_project", {"keyword": "x" * 201})
        ])
        with self.assertRaises(ValueError) as ctx:
            main.parse_tool_plan(content)
        self.assertIn("超出长度上限", str(ctx.exception))

    def test_keyword_at_limit_is_allowed(self):
        content = self._plan_json([
            self._item("search_project", {"keyword": "x" * 200})
        ])
        plan = main.parse_tool_plan(content)
        self.assertEqual(len(plan), 1)

    def test_invalid_keyword_does_not_traverse_directories(self):
        main.AUTHORIZED_PERMISSION = "read"

        with mock.patch.object(Path, "rglob") as spy:
            with self.assertRaises(ValueError):
                main.search_project("proj", 123)

        spy.assert_not_called()

    def test_empty_keyword_does_not_traverse_directories(self):
        main.AUTHORIZED_PERMISSION = "read"

        with mock.patch.object(Path, "rglob") as spy:
            with self.assertRaises(ValueError):
                main.search_project("proj", "   ")

        spy.assert_not_called()

    # ------------------------------------------------------------------
    # 正常路径与既有防线不受影响
    # ------------------------------------------------------------------

    def test_normal_read_plans_still_parse(self):
        content = self._plan_json([
            self._item("read_project", ...),
            self._item("read_file", {"relative_path": "a.txt"}),
            self._item("search_project", {"keyword": "hello"}),
        ])
        plan = main.parse_tool_plan(content)
        self.assertEqual([p["name"] for p in plan],
                         ["read_project", "read_file", "search_project"])

    def test_unknown_field_still_rejected(self):
        content = self._plan_json([
            self._item("read_file",
                       {"relative_path": "a.txt", "extra": 1})
        ])
        with self.assertRaises(PermissionError) as ctx:
            main.parse_tool_plan(content)
        self.assertIn("未经允许的参数", str(ctx.exception))

    def test_unknown_tool_still_rejected(self):
        content = self._plan_json([self._item("delete_all", {})])
        with self.assertRaises(PermissionError) as ctx:
            main.parse_tool_plan(content)
        self.assertIn("未知工具", str(ctx.exception))

    def test_read_only_whitelist_still_rejects_modify_file(self):
        content = self._plan_json([
            self._item("modify_file", {
                "relative_path": "a.txt",
                "old_text": "hello",
                "new_text": "HELLO",
            })
        ])
        with self.assertRaises(PermissionError) as ctx:
            main.parse_tool_plan(content, allowed_tools=main.ALLOWED_READ_TOOLS)
        self.assertIn("本轮计划不允许使用该工具", str(ctx.exception))

    def test_no_side_effects_on_rejection(self):
        content = self._plan_json([self._item("search_project",
                                              {"keyword": 123})])
        with self.assertRaises(ValueError):
            main.parse_tool_plan(content)
        self.assertEqual(self.target_bytes(), b"hello\n")
        self.assertEqual(self.backups(self.project), [])

    def target_bytes(self):
        return (self.project / "a.txt").read_bytes()


if __name__ == "__main__":
    unittest.main()
