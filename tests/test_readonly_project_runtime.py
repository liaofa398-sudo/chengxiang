"""D-5.18-A1-P3：只读工具运行时行为回归测试。

将 D-5.18-A1-P1 的 R1–R8 手工验证转化为自动化回归保护。

隔离约定：
- 全部使用 ChengxiangTestBase 的临时 HOME / BASE_DIR / PROJECTS_FILE / AUDIT_FILE；
- 不引用真实目录 /root/chengxiang_d518；
- 授权通过真实 main.authorize() 建立、main.clear_authorization() 清理，
  不伪造 PLAN_APPROVAL，不直接改写权限全局。

审计判据（D-5.18-A1-P2 修订版）：
- read_file / search_project 自身不得产生审计事件；
- authorization_cleared 允许出现，但必须对应一次真实清理；
- 无授权时 clear_authorization() 不产生事件；
- 不允许其他未预期事件。
"""

import io
import unittest
from contextlib import redirect_stdout
from unittest import mock

import main
from tests.support import ChengxiangTestBase


class ReadonlyProjectRuntimeTests(ChengxiangTestBase):
    def setUp(self):
        super().setUp()
        self.project = self.setup_project("proj")

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    def _authorize_read(self):
        """通过真实公开接口建立只读授权（不直接改写全局）。"""
        with redirect_stdout(io.StringIO()):
            main.authorize("read")
        self.assertEqual(main.AUTHORIZED_PERMISSION, "read")

    def _assert_no_authorization(self):
        self.assertIsNone(main.AUTHORIZED_PERMISSION)
        self.assertIsNone(main.PLAN_APPROVAL)

    def _modify_plan(self):
        return [
            {
                "name": "modify_file",
                "project_id": "proj",
                "args": {
                    "relative_path": "a.txt",
                    "old_text": "hello",
                    "new_text": "HELLO",
                },
            }
        ]

    # ------------------------------------------------------------------
    # T1 正常读取文本文件
    # ------------------------------------------------------------------

    def test_read_file_returns_text_content(self):
        self.make_file(self.project, "a.txt", "hello readonly")
        self._authorize_read()

        result = main.read_file("proj", "a.txt")

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["content"], "hello readonly")
        self.assertEqual(result["file"], "a.txt")
        self.assertEqual(result["project"], "proj")

        main.clear_authorization()
        self._assert_no_authorization()

    # ------------------------------------------------------------------
    # T2 读取 Python 源码但不执行
    # ------------------------------------------------------------------

    def test_read_file_returns_python_source_without_execution(self):
        canary = self.project / "canary.txt"
        source = 'open({}, "w").write("SHOULD_NOT_RUN")\n'.format(
            repr(str(canary))
        )
        self.make_file(self.project, "canary.py", source)
        self._authorize_read()

        result = main.read_file("proj", "canary.py")

        # 返回的是源码文本
        self.assertEqual(result["status"], "ok")
        self.assertIn("SHOULD_NOT_RUN", result["content"])
        self.assertIn("open(", result["content"])
        # 副作用没有发生（可观测断言，而非"没抛异常"）
        self.assertFalse(
            canary.exists(), "诱饵源码被读取时被执行了（副作用已产生）"
        )

        main.clear_authorization()
        self._assert_no_authorization()

    # ------------------------------------------------------------------
    # T3 搜索命中关键词
    # ------------------------------------------------------------------

    def test_search_project_hits_keyword_in_file(self):
        self.make_file(self.project, "notes.txt", "青龙在这里\n")
        self.make_file(self.project, "other.txt", "无关内容\n")
        self._authorize_read()

        result = main.search_project("proj", "青龙")

        self.assertEqual(result["count"], 1)
        self.assertEqual(result["results"][0]["file"], "notes.txt")
        self.assertIn("青龙", result["results"][0]["text"])

        main.clear_authorization()
        self._assert_no_authorization()

    # ------------------------------------------------------------------
    # T4 搜索无匹配
    # ------------------------------------------------------------------

    def test_search_project_returns_empty_when_no_match(self):
        self.make_file(self.project, "notes.txt", "青龙在这里\n")
        self._authorize_read()

        result = main.search_project("proj", "NO_SUCH_KEYWORD_D518")

        self.assertEqual(result["count"], 0)
        self.assertEqual(result["results"], [])

        main.clear_authorization()
        self._assert_no_authorization()

    # ------------------------------------------------------------------
    # T5 拒绝越界读取
    # ------------------------------------------------------------------

    def test_read_file_rejects_escaping_relative_path(self):
        self.make_file(self.project, "a.txt", "hello\n")
        self._authorize_read()

        with self.assertRaises(PermissionError) as ctx:
            main.read_file("proj", "../outside.txt")

        self.assertIn("项目目录之外", str(ctx.exception))

        main.clear_authorization()
        self._assert_no_authorization()

    # ------------------------------------------------------------------
    # T6 拒绝 .env（文件不存在，仍应报敏感路径而非"不存在"）
    # ------------------------------------------------------------------

    def test_read_file_rejects_env_before_existence_check(self):
        self.assertFalse((self.project / ".env").exists())
        self._authorize_read()

        with self.assertRaises(PermissionError) as ctx:
            main.read_file("proj", ".env")

        message = str(ctx.exception)
        self.assertIn("敏感路径", message)
        self.assertNotIn("不存在", message)

        main.clear_authorization()
        self._assert_no_authorization()

    # ------------------------------------------------------------------
    # T7 拒绝 .git 组件
    # ------------------------------------------------------------------

    def test_read_file_rejects_git_component(self):
        self.assertFalse((self.project / ".git").exists())
        self._authorize_read()

        with self.assertRaises(PermissionError) as ctx:
            main.read_file("proj", ".git/config")

        message = str(ctx.exception)
        self.assertIn("敏感路径", message)
        self.assertNotIn("不存在", message)

        main.clear_authorization()
        self._assert_no_authorization()

    # ------------------------------------------------------------------
    # T8 只读权限无法绑定修改计划
    # ------------------------------------------------------------------

    def test_read_permission_cannot_bind_modify_plan(self):
        self._authorize_read()

        with self.assertRaises(PermissionError) as ctx:
            main.bind_plan_approval(self._modify_plan(), "read", "human")

        self.assertIn("modify", str(ctx.exception))
        self.assertIsNone(main.PLAN_APPROVAL)

        main.clear_authorization()
        self._assert_no_authorization()

    # ------------------------------------------------------------------
    # T9 绑定拒绝时 modify_file 调用次数为零
    # ------------------------------------------------------------------

    def test_modify_file_never_called_when_bind_rejected(self):
        self.make_file(self.project, "a.txt", "hello\n")
        before = (self.project / "a.txt").read_bytes()
        self._authorize_read()

        with mock.patch.object(main, "modify_file") as spy:
            with self.assertRaises(PermissionError):
                main.bind_plan_approval(self._modify_plan(), "read", "human")

        self.assertEqual(spy.call_count, 0)
        self.assertIsNone(main.PLAN_APPROVAL)
        self.assertEqual(self.backups(self.project), [])
        self.assertEqual((self.project / "a.txt").read_bytes(), before)

        main.clear_authorization()
        self._assert_no_authorization()

    # ------------------------------------------------------------------
    # T10 只读工具不产生审计事件
    # ------------------------------------------------------------------

    def test_read_tools_emit_no_audit_events(self):
        self.make_file(self.project, "a.txt", "hello 青龙\n")
        self._authorize_read()

        with mock.patch.object(main, "audit_event") as spy:
            read_result = main.read_file("proj", "a.txt")
            search_result = main.search_project("proj", "青龙")
            # 只读工具调用过程内统计，不得混入清理事件
            self.assertEqual(spy.call_count, 0)

        self.assertEqual(read_result["status"], "ok")
        self.assertEqual(search_result["count"], 1)

        main.clear_authorization()
        self._assert_no_authorization()

    # ------------------------------------------------------------------
    # T11 清理审计：仅有授权时产生，且每次真实清理恰一条
    # ------------------------------------------------------------------

    def test_clear_authorization_audits_only_when_authorized(self):
        with mock.patch.object(main, "audit_event") as spy:
            # 第一段：无授权
            self.assertIsNone(main.AUTHORIZED_PERMISSION)
            self.assertIsNone(main.PLAN_APPROVAL)
            main.clear_authorization()
            self.assertEqual(spy.call_count, 0)

            # 第二段：存在授权
            with redirect_stdout(io.StringIO()):
                main.authorize("read")
            main.clear_authorization()
            self.assertEqual(spy.call_count, 1)
            self.assertEqual(spy.call_args.args[0], "authorization_cleared")

            # 再次清理不得新增
            main.clear_authorization()
            self.assertEqual(spy.call_count, 1)

        events = [call.args[0] for call in spy.call_args_list]
        self.assertEqual(set(events), {"authorization_cleared"})

        self._assert_no_authorization()


if __name__ == "__main__":
    unittest.main()
