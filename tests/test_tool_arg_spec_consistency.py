"""D-5.15-B1：TOOL_ARG_SPEC 契约一致性测试。

parser 与 executor 现在共用 TOOL_ARG_SPEC 作为参数键集合的唯一来源，
本文件把该契约钉死，防止未来只改一处造成漂移。

不涉及文件系统、网络或授权状态，因此不需要 ChengxiangTestBase。
"""

import unittest

import main


class ToolArgSpecConsistencyTests(unittest.TestCase):
    def test_spec_covers_exactly_allowed_tools(self):
        self.assertEqual(
            set(main.TOOL_ARG_SPEC),
            set(main.ALLOWED_TOOLS),
            "TOOL_ARG_SPEC 与 ALLOWED_TOOLS 必须一一对应",
        )

    def test_required_and_optional_are_frozensets(self):
        for name, spec in main.TOOL_ARG_SPEC.items():
            with self.subTest(tool=name):
                self.assertIsInstance(spec, dict)
                self.assertIsInstance(spec["required"], frozenset)
                self.assertIsInstance(spec["optional"], frozenset)

    def test_required_and_optional_are_disjoint(self):
        for name, spec in main.TOOL_ARG_SPEC.items():
            with self.subTest(tool=name):
                self.assertEqual(
                    spec["required"] & spec["optional"],
                    frozenset(),
                    f"{name} 的 required 与 optional 不得有交集",
                )

    def test_contracts_match_approved_table(self):
        expected = {
            "read_project": (frozenset(), frozenset()),
            "read_file": (
                frozenset({"relative_path"}),
                frozenset({"start_line", "end_line"}),
            ),
            "search_project": (frozenset({"keyword"}), frozenset()),
            "modify_file": (
                frozenset({"relative_path", "old_text", "new_text"}),
                frozenset(),
            ),
        }

        self.assertEqual(set(main.TOOL_ARG_SPEC), set(expected))

        for name, (required, optional) in expected.items():
            with self.subTest(tool=name):
                self.assertEqual(
                    main.TOOL_ARG_SPEC[name]["required"], required
                )
                self.assertEqual(
                    main.TOOL_ARG_SPEC[name]["optional"], optional
                )


if __name__ == "__main__":
    unittest.main()
