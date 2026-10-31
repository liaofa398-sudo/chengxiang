"""测试支撑：隔离工作区、替换并恢复模块全局。

所有测试都在临时目录内进行，绝不触碰真实的 ~/chengxiang。
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import main  # noqa: E402


class ChengxiangTestBase(unittest.TestCase):
    """每个用例一套独立的 Home / BASE_DIR / projects.json / audit.jsonl。"""

    _GLOBALS = (
        "BASE_DIR",
        "PROJECTS_FILE",
        "AUDIT_FILE",
        "AUTHORIZED_PERMISSION",
        "STATE",
        "CURRENT_TOOL_PLAN",
        "PLAN_APPROVAL",
    )

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.tmp = Path(self._tmpdir.name)

        self._saved = {name: getattr(main, name) for name in self._GLOBALS}
        self._saved["HOME"] = os.environ.get("HOME")
        self._saved["CURRENT_TASK"] = dict(main.CURRENT_TASK)
        self.addCleanup(self._restore)

        self.home = self.tmp / "home"
        self.home.mkdir()

        main.BASE_DIR = self.home / "chengxiang"
        main.BASE_DIR.mkdir()
        main.PROJECTS_FILE = main.BASE_DIR / "projects.json"
        main.AUDIT_FILE = main.BASE_DIR / "audit.jsonl"
        main.AUTHORIZED_PERMISSION = None
        main.STATE = "IDLE"
        main.CURRENT_TOOL_PLAN = []
        main.PLAN_APPROVAL = None

        os.environ["HOME"] = str(self.home)

    def _restore(self):
        for name in self._GLOBALS:
            setattr(main, name, self._saved[name])
        main.CURRENT_TASK.clear()
        main.CURRENT_TASK.update(self._saved["CURRENT_TASK"])

        original_home = self._saved["HOME"]
        if original_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = original_home

    # ------------------------------------------------------------------
    # 辅助方法
    # ------------------------------------------------------------------

    def write_projects(self, projects):
        main.PROJECTS_FILE.write_text(
            json.dumps({"projects": projects}, ensure_ascii=False),
            encoding="utf-8",
        )

    def register_project(self, project_id="proj", path=None):
        project = {"name": project_id, "path": str(path) if path else None}
        self.write_projects({project_id: project})
        return project

    def make_project_dir(self, name="proj"):
        directory = self.home / name
        directory.mkdir()
        return directory

    def setup_project(self, name="proj"):
        """创建项目目录并登记到 projects.json。"""
        directory = self.home / name
        directory.mkdir()
        self.register_project(name, directory)
        return directory

    def make_file(self, directory, name, data, mode=None):
        path = directory / name
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")
        if mode is not None:
            os.chmod(path, mode)
        return path

    def backups(self, directory):
        return sorted(
            p for p in directory.iterdir()
            if p.name.endswith(".before_chengxiang_modify.bak")
        )

    def partials(self, directory):
        return sorted(
            p for p in directory.iterdir()
            if p.name.endswith(".before_chengxiang_modify.partial")
        )

    def grant(self, permission):
        # 直接设置全局，等价于 authorize() 但不产生打印与审计副作用。
        main.AUTHORIZED_PERMISSION = permission
