"""F11：参数校验——类型、长度、NUL、UTF-8 可编码性、bool 行号。"""

import json
import unittest

import main
from tests.support import ChengxiangTestBase


def plan_line(tool, args):
    payload = {
        "tools": [
            {"name": tool, "project_id": "proj", "args": args}
        ]
    }
    return "TOOL_PLAN_JSON: " + json.dumps(payload, ensure_ascii=False)


class PlanArgValidationTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.make_file(self.project, "a.txt", b"hello\n")
        self.grant("modify")

    def test_old_text_must_be_string(self):
        with self.assertRaises(ValueError):
            main.parse_tool_plan(
                plan_line(
                    "modify_file",
                    {"relative_path": "a.txt", "old_text": 123,
                     "new_text": "x"},
                )
            )

    def test_new_text_must_be_string(self):
        with self.assertRaises(ValueError):
            main.parse_tool_plan(
                plan_line(
                    "modify_file",
                    {"relative_path": "a.txt", "old_text": "h",
                     "new_text": ["x"]},
                )
            )

    def test_empty_old_text_is_rejected(self):
        with self.assertRaises(PermissionError):
            main.parse_tool_plan(
                plan_line(
                    "modify_file",
                    {"relative_path": "a.txt", "old_text": "",
                     "new_text": "x"},
                )
            )

    def test_oversized_new_text_is_rejected(self):
        with self.assertRaises(ValueError):
            main.parse_tool_plan(
                plan_line(
                    "modify_file",
                    {"relative_path": "a.txt", "old_text": "h",
                     "new_text": "x" * (main.MAX_NEW_TEXT_CHARS + 1)},
                )
            )

    def test_nul_in_old_text_is_rejected(self):
        with self.assertRaises(ValueError):
            main.parse_tool_plan(
                plan_line(
                    "modify_file",
                    {"relative_path": "a.txt", "old_text": "a\x00b",
                     "new_text": "x"},
                )
            )

    def test_surrogate_in_new_text_is_rejected(self):
        with self.assertRaises(ValueError):
            main.parse_tool_plan(
                plan_line(
                    "modify_file",
                    {"relative_path": "a.txt", "old_text": "h",
                     "new_text": "x\ud800y"},
                )
            )

    def test_relative_path_must_be_string(self):
        with self.assertRaises(ValueError):
            main.parse_tool_plan(
                plan_line(
                    "read_file",
                    {"relative_path": 5},
                )
            )

    def test_relative_path_length_is_capped(self):
        with self.assertRaises(ValueError):
            main.parse_tool_plan(
                plan_line(
                    "read_file",
                    {"relative_path": "a" * (main.MAX_RELATIVE_PATH_CHARS + 1)},
                )
            )

    def test_relative_path_nul_is_rejected(self):
        with self.assertRaises(ValueError):
            main.parse_tool_plan(
                plan_line("read_file", {"relative_path": "a\x00b"})
            )

    def test_bool_start_line_in_plan_is_rejected(self):
        with self.assertRaises(ValueError):
            main.parse_tool_plan(
                plan_line(
                    "read_file",
                    {"relative_path": "a.txt", "start_line": True,
                     "end_line": 2},
                )
            )

    def test_bool_end_line_in_plan_is_rejected(self):
        with self.assertRaises(ValueError):
            main.parse_tool_plan(
                plan_line(
                    "read_file",
                    {"relative_path": "a.txt", "start_line": 1,
                     "end_line": False},
                )
            )


class DirectCallValidationTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")
        self.make_file(self.project, "a.txt", b"hello\n")
        self.grant("modify")

    def test_modify_file_rejects_non_string_old_text(self):
        with self.assertRaises(PermissionError):
            main.modify_file("proj", "a.txt", 123, "x")
        self.assertEqual(self.backups(self.project), [])

    def test_modify_file_rejects_blank_relative_path(self):
        with self.assertRaises(PermissionError):
            main.modify_file("proj", "   ", "hello", "x")

    def test_missing_file_yields_no_backup(self):
        with self.assertRaises(FileNotFoundError):
            main.modify_file("proj", "nope.txt", "hello", "x")
        self.assertEqual(self.backups(self.project), [])

    def test_read_file_rejects_bool_line_number(self):
        main.AUTHORIZED_PERMISSION = "read"
        with self.assertRaises(ValueError):
            main.read_file("proj", "a.txt", True, 2)

    def test_read_file_rejects_bool_end_line(self):
        main.AUTHORIZED_PERMISSION = "read"
        with self.assertRaises(ValueError):
            main.read_file("proj", "a.txt", 1, False)


if __name__ == "__main__":
    unittest.main()
