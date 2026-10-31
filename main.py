import ctypes
import datetime
import errno
import fcntl
import hashlib
import json
import os
import stat
import tempfile
import urllib.request
import urllib.error
import subprocess
from pathlib import Path

BASE_DIR = Path.home() / "chengxiang"
PROJECTS_FILE = BASE_DIR / "projects.json"
ENV_FILE = BASE_DIR / ".env"

MODEL = "deepseek-flash"
BASE_URL = "https://api.deepseek.com/chat/completions"

PERMISSIONS = {
    "read": "只读：查看、分析、检查",
    "modify": "修改：创建或修改文件、代码",
    "git": "Git：commit、push、分支操作",
    "dangerous": "危险：删除、覆盖、reset、revert、部署、付费服务、密钥操作"
}

STATE = "IDLE"
AUTHORIZED_PERMISSION = None

# 当前皇帝圣旨的任务上下文
CURRENT_TASK = {
    "goal": None,
    "success_criteria": [],
    "project_id": None,
    "complexity": "unknown",
    "risk": "unknown",
    "authorization": "none",
    "stage": "idle",
    "completed_steps": [],
}

def reset_current_task():
    """清空已终止任务的上下文，不触碰授权或工具计划。"""
    CURRENT_TASK.update({
        "goal": None,
        "success_criteria": [],
        "project_id": None,
        "complexity": "unknown",
        "risk": "unknown",
        "authorization": "none",
        "stage": "idle",
        "completed_steps": [],
    })



# ============================================================
# 审计日志：只记录事件元数据，不记录对话正文或工具参数
# ============================================================

AUDIT_FILE = BASE_DIR / "audit.jsonl"

AUDIT_EVENTS = {
    "approval_bound",
    "approval_rejected",
    "execution_started",
    "tool_succeeded",
    "tool_failed",
    "tool_not_executed",
    "execution_finished",
    "authorization_cleared",
}

AUDIT_FIELDS = {
    "project_id",
    "permission",
    "source",
    "tool",
    "status",
    "index",
    "error_type",
    "reason",
}


def audit_event(event, **fields):
    """向权限为 600 的 JSONL 文件追加一条最小化审计事件。"""
    if event not in AUDIT_EVENTS:
        raise ValueError("拒绝未知审计事件。")

    unknown = set(fields) - AUDIT_FIELDS
    if unknown:
        raise ValueError("拒绝未允许的审计字段。")

    record = {
        "timestamp": __import__("datetime").datetime.now().astimezone().isoformat(),
        "event": event,
    }

    project_id = CURRENT_TASK.get("project_id")
    if isinstance(project_id, (str, int)) and str(project_id):
        record["project_id"] = str(project_id)[:100]

    for key, value in fields.items():
        if value is None:
            continue
        if key == "index":
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError("审计 index 必须为非负整数。")
            record[key] = value
        else:
            if not isinstance(value, (str, int, bool)):
                raise ValueError("拒绝非简单类型的审计字段。")
            record[key] = str(value)[:200]

    payload = (
        json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")

    path = AUDIT_FILE
    if os.path.lexists(path) and path.is_symlink():
        raise OSError("拒绝写入符号链接审计日志。")

    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("审计目标不是普通文件。")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise OSError("审计日志权限必须为 600。")

        written = os.write(fd, payload)
        if written != len(payload):
            raise OSError("审计记录未完整写入。")
        os.fsync(fd)
    except BaseException:
        # 有异常在飞：关闭失败不得覆盖它，原始异常原样上抛。
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    else:
        os.close(fd)




# ============================================================
# 基础配置
# ============================================================

def load_env():
    if not ENV_FILE.exists():
        return {}

    result = {}

    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()

        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()

    return result


def load_projects():
    if not PROJECTS_FILE.exists():
        return {}

    with open(PROJECTS_FILE, "r", encoding="utf-8") as f:
        return json.load(f).get("projects", {})


# ============================================================
# 中央权限层
# ============================================================

def permission_level(permission):
    order = {
        "read": 1,
        "modify": 2,
        "git": 3,
        "dangerous": 4
    }

    # 未知权限必须显式拒绝：绝不能默认成最高等级或任何有效等级。
    if permission not in order:
        raise ValueError(f"拒绝未知权限：{permission!r}。")

    return order[permission]


def authorize(permission):
    """
    授权只能由皇帝明确触发。
    不允许工具自行提升权限。
    """
    global AUTHORIZED_PERMISSION

    if permission not in PERMISSIONS:
        raise PermissionError(f"拒绝未知权限：{permission!r}。")

    AUTHORIZED_PERMISSION = permission
    print(f"🔐 已授予本次任务权限：{permission}")


def clear_authorization():
    """收回授权变量。

    只负责清理 AUTHORIZED_PERMISSION 与 PLAN_APPROVAL；
    STATE 由调用方显式设置（例如 "IDLE" 或 "EXIT"），
    本函数不写入 STATE，以免覆盖 "EXIT" 等合法终态。
    """
    global AUTHORIZED_PERMISSION, PLAN_APPROVAL

    had_authorization = (
        AUTHORIZED_PERMISSION is not None or PLAN_APPROVAL is not None
    )

    # 先收回权限；审计失败也不能阻止清理。
    AUTHORIZED_PERMISSION = None
    PLAN_APPROVAL = None

    if had_authorization:
        try:
            audit_event(
                "authorization_cleared",
                source="system",
                status="cleared",
            )
        except Exception as audit_exc:
            print(
                "⚠️ 授权已收回，但审计日志写入失败："
                f"{type(audit_exc).__name__}"
            )


def require_permission(required):
    """
    工具执行前的中央权限检查。
    """
    if AUTHORIZED_PERMISSION is None:
        raise PermissionError(
            f"未获授权：需要 {required} 权限，目前没有任何执行权限。"
        )

    if AUTHORIZED_PERMISSION not in PERMISSIONS:
        raise PermissionError(
            f"拒绝未知权限：{AUTHORIZED_PERMISSION!r}。"
        )

    if required not in PERMISSIONS:
        raise PermissionError(
            f"拒绝未知的目标权限：{required!r}。"
        )

    if permission_level(AUTHORIZED_PERMISSION) < permission_level(required):
        raise PermissionError(
            f"权限不足：工具需要 {required}，"
            f"当前仅授权 {AUTHORIZED_PERMISSION}。"
        )


# ============================================================
# 第一枚兵符：只读工具
# ============================================================

def _path_is_within(child, parent):
    """child 是否等于 parent 或位于其下；两者均须为已 resolve 的 Path。"""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _stat_identity(path):
    """返回 path 的 (st_dev, st_ino)。

    - 路径不存在（含 ENOTDIR）：返回 None —— 这是确定的"不是同一对象"。
    - 其它任何 OSError（EACCES / EIO / ELOOP ...）：抛 PermissionError。
      无法确认安全时必须拒绝，不得降级为放行。
    """
    try:
        info = os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as exc:
        raise PermissionError(
            f"无法确认路径的文件系统身份，拒绝继续：{path}"
            f"（{type(exc).__name__}）"
        ) from exc

    return (info.st_dev, info.st_ino)


def safe_project_path(project):
    """
    根据户籍解析项目路径。

    当前只允许明确登记过的本地 path。
    repository / Codespace 暂时不执行实际访问。

    安全边界共三条：
    1. 必须位于当前用户 Home 目录之下。
    2. 不得指向丞相府自身目录（BASE_DIR），也不得是其上级或下级目录。
    3. 不得与上述目录指向同一文件系统对象（大小写不敏感文件系统、
       绑定挂载等造成的路径别名）。
    """
    path = project.get("path")

    if not path:
        return None

    expanded = Path(path).expanduser().resolve()

    # 边界一：当前只允许访问用户 Home 目录下的路径。
    home = Path.home().resolve()

    if not _path_is_within(expanded, home):
        raise PermissionError(
            "项目路径超出当前用户 Home 目录，拒绝读取。"
        )

    # 边界二：字面边界——丞相府自身目录及其祖先、子孙。
    # BASE_DIR 在调用时读取模块全局，便于测试替换。
    base = Path(BASE_DIR).resolve()

    if _path_is_within(expanded, base) or _path_is_within(base, expanded):
        raise PermissionError(
            "项目路径不得指向丞相府自身目录，"
            "也不得是包含丞相府目录的上级目录。"
        )

    # 边界三：别名边界。判定完成之后才抛，避免被任何 except OSError 吞掉。
    expanded_id = _stat_identity(expanded)
    alias_hit = False

    if expanded_id is not None:
        for candidate_dir in (base, *base.parents):
            candidate_id = _stat_identity(candidate_dir)
            if candidate_id is not None and candidate_id == expanded_id:
                alias_hit = True
                break

    if alias_hit:
        raise PermissionError(
            "项目路径与丞相府目录或其上级目录指向同一文件系统对象，拒绝。"
        )

    return expanded



# ============================================================
# 只读安全边界
# ============================================================

FORBIDDEN_READ_NAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "credentials.json",
    "secrets.json",
}

FORBIDDEN_READ_SUFFIXES = {
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".token",
}

IGNORED_SEARCH_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
}

# ------------------------------------------------------------
# 参数与备份的硬上限
# ------------------------------------------------------------

MAX_OLD_TEXT_CHARS = 200_000
MAX_NEW_TEXT_CHARS = 2_000_000
MAX_RELATIVE_PATH_CHARS = 4096
MAX_SEARCH_KEYWORD_CHARS = 200
MAX_BACKUP_ATTEMPTS = 5

# modify_file 的输入上限：与 read_file 的整体读取上限保持一致。
MAX_MODIFY_FILE_BYTES = 8 * 1024 * 1024
MODIFY_READ_CHUNK_BYTES = 1024 * 1024


def _read_bounded(fd, limit):
    """从已打开的 fd 读取至多 limit 字节。

    返回的 bytes 长度恒 <= limit；不做"先整体读入再判断"。
    """
    buffers = []
    remaining = limit

    while remaining > 0:
        chunk = os.read(fd, min(remaining, MODIFY_READ_CHUNK_BYTES))
        if not chunk:
            break
        buffers.append(chunk)
        remaining -= len(chunk)

    return b"".join(buffers)


def _validate_text_arg(name, value, max_chars):
    """校验字符串参数：类型、长度、NUL、UTF-8 可编码性。"""
    if not isinstance(value, str):
        raise ValueError(f"{name} 必须是字符串。")
    if len(value) > max_chars:
        raise ValueError(f"{name} 超出长度上限 {max_chars} 字符。")
    if "\x00" in value:
        raise ValueError(f"{name} 不得包含 NUL 字符。")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} 含无法编码为 UTF-8 的字符。") from exc


def _validate_relative_path(value):
    """校验项目内相对路径的字符串层面约束。"""
    _validate_text_arg("relative_path", value, MAX_RELATIVE_PATH_CHARS)
    if not value.strip():
        raise PermissionError("拒绝空白或无效的目标路径。")


def _validate_line_number(name, value):
    """校验行号，并拒绝 bool 被当作整数行号（bool 是 int 的子类）。"""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} 必须是整数。")
    if value < 1:
        raise ValueError(f"{name} 必须 >= 1。")


def is_forbidden_read(path):
    """
    中央只读安全门。
    即使 DeepSeek 要求读取，也不能读取明显的密钥文件。
    """
    name = path.name.lower()

    if name in FORBIDDEN_READ_NAMES:
        return True

    if any(name.endswith(suffix) for suffix in FORBIDDEN_READ_SUFFIXES):
        return True

    return False


def get_registered_project(project_id):
    projects = load_projects()

    if project_id not in projects:
        raise ValueError(f"户籍中不存在项目：{project_id}")

    return projects[project_id]


def get_local_project_root(project_id):
    project = get_registered_project(project_id)
    path = safe_project_path(project)

    if path is None:
        raise ValueError(
            f"项目 {project_id} 当前没有登记本地 path，"
            "暂不能使用本地只读兵符。"
        )

    if not path.exists():
        raise FileNotFoundError(
            f"项目路径不存在：{path}"
        )

    if not path.is_dir():
        raise ValueError(
            f"项目路径不是目录：{path}"
        )

    return path


MAX_READ_FILE_BYTES = 8 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_SCAN_LINES = 200_000
MAX_RETURN_LINES = 500


def _read_line_range(target, relative_path, project_id,
                     start_line, end_line, max_bytes):
    """以固定大小二进制块逐行读取指定行范围。

    不变量：
    - 每次 read() 的实参恒为 READ_CHUNK_BYTES；
    - buf 仅在"当前行位于请求范围内"时非空，且长度恒 <= max_bytes；
    - 范围外的行完全不缓冲，只统计换行符；
    - 任一项限额越界都抛受控 ValueError，绝不无限读取。

    由于 buffering=0，read() 不做预读，scanned_bytes 是精确值。
    """
    collected = []
    collected_bytes = 0
    line_no = 0
    scanned_bytes = 0
    buf = bytearray()
    skipping = False

    with target.open("rb", buffering=0) as handle:
        while True:
            chunk = handle.read(READ_CHUNK_BYTES)
            if not chunk:
                break

            scanned_bytes += len(chunk)
            if scanned_bytes > MAX_SCAN_BYTES:
                raise ValueError(
                    f"扫描字节数超过上限 {MAX_SCAN_BYTES} bytes，已中止。"
                    "请改用 search_project 定位。"
                )

            pos = 0
            while pos < len(chunk):
                in_range = start_line <= line_no + 1 <= end_line

                if in_range:
                    idx = chunk.find(b"\n", pos)
                    end = len(chunk) if idx < 0 else idx

                    # 扩写前预检：越过可返回预算即确定失败。
                    remaining = max_bytes - collected_bytes
                    if len(buf) + (end - pos) > remaining:
                        raise ValueError(
                            f"第 {line_no + 1} 行的可返回字节预算不足："
                            f"已累积 {len(buf)} bytes，"
                            f"本块将增加 {end - pos} bytes，"
                            f"剩余预算 {remaining} bytes，已中止。"
                        )

                    buf.extend(chunk[pos:end])
                    skipping = False

                    if idx < 0:
                        pos = len(chunk)
                    else:
                        line_no += 1
                        if line_no > MAX_SCAN_LINES:
                            raise ValueError(
                                f"扫描行数超过上限 {MAX_SCAN_LINES} 行，已中止。"
                            )
                        text = (
                            bytes(buf)
                            .decode("utf-8", errors="replace")
                            .rstrip("\r")
                        )
                        collected.append(text)
                        collected_bytes += len(text.encode("utf-8")) + 1
                        buf.clear()
                        pos = idx + 1
                else:
                    idx = chunk.find(b"\n", pos)
                    if idx < 0:
                        pos = len(chunk)
                        skipping = True
                    else:
                        line_no += 1
                        if line_no > MAX_SCAN_LINES:
                            raise ValueError(
                                f"扫描行数超过上限 {MAX_SCAN_LINES} 行，已中止。"
                            )
                        skipping = False
                        pos = idx + 1

        # EOF：处理文件末尾没有换行符的最后一行。
        if buf:
            line_no += 1
            if line_no > MAX_SCAN_LINES:
                raise ValueError(
                    f"扫描行数超过上限 {MAX_SCAN_LINES} 行，已中止。"
                )
            text = (
                bytes(buf).decode("utf-8", errors="replace").rstrip("\r")
            )
            collected.append(text)
            collected_bytes += len(text.encode("utf-8")) + 1
        elif skipping:
            line_no += 1
            if line_no > MAX_SCAN_LINES:
                raise ValueError(
                    f"扫描行数超过上限 {MAX_SCAN_LINES} 行，已中止。"
                )

    total_lines = line_no

    if start_line > total_lines:
        raise ValueError(
            f"start_line 超出文件范围：文件共 {total_lines} 行。"
        )

    end_line = min(end_line, total_lines)
    result_content = "\n".join(collected)

    if len(result_content.encode("utf-8")) > max_bytes:
        raise ValueError(
            f"指定行范围过大，单次最多返回 {max_bytes} bytes。"
        )

    return {
        "project": project_id,
        "status": "ok",
        "file": relative_path,
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": total_lines,
        "bytes": len(result_content.encode("utf-8")),
        "content": result_content,
    }


def read_file(project_id, relative_path, start_line=None, end_line=None, max_bytes=30000):
    """
    精确读取项目内的单个文本文件。
    支持可选行范围：
    start_line / end_line 均为 1-based，包含首尾。

    整体读取有 MAX_READ_FILE_BYTES 硬上限；
    行范围读取采用固定块二进制读取、逐行处理，
    同时限制扫描字节数、扫描行数、返回行数与返回字节数。
    """
    require_permission("read")

    _validate_relative_path(relative_path)

    root = get_local_project_root(project_id)

    target = (root / relative_path).resolve()

    try:
        resolved_relative = target.relative_to(root)
    except ValueError:
        raise PermissionError(
            "拒绝读取项目目录之外的文件。"
        )

    # 检查解析后的完整路径，防止通过子目录或符号链接
    # 访问 .git、密钥文件及其他中央禁止读取的目标。
    for component in resolved_relative.parts:
        name = component.lower()
        if (
            name == ".git"
            or name in FORBIDDEN_READ_NAMES
            or any(
                name.endswith(suffix)
                for suffix in FORBIDDEN_READ_SUFFIXES
            )
        ):
            raise PermissionError(
                f"拒绝读取敏感路径：{relative_path}"
            )

    if not target.exists():
        raise FileNotFoundError(
            f"文件不存在：{relative_path}"
        )

    if not target.is_file():
        raise ValueError(
            f"目标不是普通文件：{relative_path}"
        )

    size = target.stat().st_size

    if start_line is not None or end_line is not None:
        if start_line is None:
            start_line = 1

        _validate_line_number("start_line", start_line)

        if end_line is None:
            end_line = start_line + 200

        _validate_line_number("end_line", end_line)

        if end_line < start_line:
            raise ValueError("行范围无效。")

        if end_line - start_line + 1 > MAX_RETURN_LINES:
            raise ValueError("单次最多读取 500 行。")

        return _read_line_range(
            target, relative_path, project_id,
            start_line, end_line, max_bytes,
        )

    # 整体读取：必须在读取之前完成大小校验。
    if size > MAX_READ_FILE_BYTES:
        raise ValueError(
            f"文件过大：{relative_path} ({size} bytes)，"
            f"超过整体读取上限 {MAX_READ_FILE_BYTES} bytes。"
            "请改用 search_project 定位，或使用 start_line/end_line 分段读取。"
        )

    if size > max_bytes:
        raise ValueError(
            f"文件过大：{relative_path} ({size} bytes)，"
            f"单次最多读取 {max_bytes} bytes。"
        )

    try:
        content = target.read_text(
            encoding="utf-8",
            errors="replace"
        )
    except OSError as e:
        raise RuntimeError(
            f"读取文件失败：{e}"
        )

    return {
        "project": project_id,
        "status": "ok",
        "file": relative_path,
        "bytes": size,
        "content": content
    }



def search_project(project_id, keyword, max_results=50):
    """
    在已登记项目中进行只读文本搜索。
    自动跳过敏感文件、Git、依赖目录和虚拟环境。
    """
    require_permission("read")

    root = get_local_project_root(project_id)

    # 入口再校验一次：必须在任何目录遍历之前完成类型与长度检查。
    _validate_text_arg("keyword", keyword, MAX_SEARCH_KEYWORD_CHARS)

    if not keyword.strip():
        raise ValueError("搜索关键词不能为空。")

    results = []

    for path in root.rglob("*"):
        if len(results) >= max_results:
            break

        # 跳过符号链接，避免搜索时读取链接目标。
        if path.is_symlink():
            continue

        # 解析真实路径，确保目标仍位于项目根目录内。
        try:
            path.resolve().relative_to(root.resolve())
        except (OSError, ValueError, RuntimeError):
            continue

        if not path.is_file():
            continue

        try:
            relative = path.relative_to(root)
        except ValueError:
            continue

        # 跳过整个目录树中的特殊目录
        if any(part in IGNORED_SEARCH_DIRS for part in relative.parts):
            continue

        # 敏感文件硬拒绝
        if is_forbidden_read(path):
            continue

        try:
            size = path.stat().st_size
        except OSError:
            continue

        # 二进制/超大文件不参与普通文本搜索
        if size > 300 * 1024:
            continue

        try:
            text = path.read_text(
                encoding="utf-8",
                errors="replace"
            )
        except (OSError, UnicodeError):
            continue

        if keyword.lower() not in text.lower():
            continue

        lines = text.splitlines()

        for number, line in enumerate(lines, 1):
            if keyword.lower() in line.lower():
                results.append({
                    "file": str(relative),
                    "line": number,
                    "text": line[:500]
                })

                if len(results) >= max_results:
                    break

    return {
        "project": project_id,
        "status": "ok",
        "keyword": keyword,
        "results": results,
        "count": len(results)
    }


def read_project(project_id):
    """
    只读项目勘察。

    当前能力：
    - 检查项目目录
    - 列出一级目录/文件
    - Git 状态
    - 不修改任何内容
    """
    require_permission("read")

    projects = load_projects()

    if project_id not in projects:
        raise ValueError(f"户籍中不存在项目：{project_id}")

    project = projects[project_id]

    path = safe_project_path(project)

    if path is None:
        return {
            "project": project_id,
            "status": "not_locally_accessible",
            "message": (
                "该项目当前没有登记本地 path，"
                "第一版只读兵符无法直接访问。"
            )
        }

    if not path.exists():
        return {
            "project": project_id,
            "status": "path_missing",
            "path": str(path),
            "message": "登记路径不存在。"
        }

    result = {
        "project": project_id,
        "status": "ok",
        "path": str(path),
        "entries": [],
        "git_status": None
    }

    # 只读取一级目录
    try:
        entries = sorted(
            path.iterdir(),
            key=lambda p: (not p.is_dir(), p.name.lower())
        )

        for entry in entries[:200]:
            result["entries"].append({
                "name": entry.name,
                "type": "directory" if entry.is_dir() else "file"
            })

    except OSError as e:
        result["directory_error"] = str(e)

    # Git 状态：只读 subprocess
    git_dir = path / ".git"

    if git_dir.exists():
        import subprocess

        try:
            completed = subprocess.run(
                ["git", "-C", str(path), "status", "--short", "--branch"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )

            result["git_status"] = {
                "returncode": completed.returncode,
                "output": completed.stdout[:10000],
                "error": completed.stderr[:2000]
            }

        except Exception as e:
            result["git_status"] = {
                "error": str(e)
            }

    return result


# ============================================================
# DeepSeek：只负责规划
# ============================================================

def parse_task_assessment(content):
    """
    解析丞相对当前任务的内部判断。

    这里只负责读取和验证任务信息：
    - goal：任务目标
    - success_criteria：成功标准
    - complexity：任务复杂度
    - risk：风险等级

    不能通过这里获得任何执行权限。
    """
    marker = "TASK_ASSESSMENT_JSON:"
    line = None

    for raw_line in content.splitlines():
        if raw_line.strip().startswith(marker):
            line = raw_line.strip()[len(marker):].strip()
            break

    if not line:
        return None

    try:
        assessment = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(assessment, dict):
        return None

    goal = assessment.get("goal")
    success_criteria = assessment.get("success_criteria", [])
    complexity = assessment.get("complexity")
    risk = assessment.get("risk")

    if not isinstance(goal, str) or not goal.strip():
        return None

    if not isinstance(success_criteria, list):
        return None

    if complexity not in {"simple", "normal", "complex"}:
        return None

    if risk not in {"low", "medium", "high", "dangerous"}:
        return None

    return {
        "goal": goal.strip(),
        "success_criteria": [
            str(item).strip()
            for item in success_criteria
            if str(item).strip()
        ],
        "complexity": complexity,
        "risk": risk,
    }


def call_deepseek(user_command, thinking_enabled=False):
    env = load_env()
    api_key = env.get("DEEPSEEK_API_KEY", "").strip()

    if not api_key:
        raise RuntimeError("DEEPSEEK_API_KEY 未配置")

    projects = load_projects()

    project_summary = json.dumps(
        projects,
        ensure_ascii=False,
        indent=2
    )

    system_prompt = f"""
你是“丞相”，负责辅助皇帝管理软件项目。

你现在处于中央集权架构。

你的职责：
1. 理解皇帝的自然语言命令。
2. 判断涉及哪个项目。
3. 制定执行计划。
4. 判断是否需要调用工具。
5. 估算 Token、风险和权限。
6. 向皇帝请旨。

当前已有只读工具：

read_project(project_id)
作用：
- 只读检查已登记项目
- 查看项目目录
- 查看 Git status
- 不修改文件

read_file(project_id, relative_path)
作用：
- 精确读取项目中的一个文本文件
- 只能读取项目目录内部
- 禁止路径逃逸
- 禁止读取 .env、密钥、token、证书等敏感文件
- 单文件有大小限制
- 如果文件可能较大，禁止直接请求整文件读取
- 对大型文件必须使用 start_line 和 end_line 分段读取
- 如果尚不知道文件大小，优先使用 read_project 或 search_project 定位，再分段读取
- 不要为了读取完整文件而一次请求整个大型文件
- 不修改文件

search_project(project_id, keyword)
作用：
- 在项目代码中进行只读关键词搜索
- 自动跳过 .git、node_modules、虚拟环境
- 自动跳过敏感文件
- 不修改文件

工具使用规则：
- 只选择完成当前任务真正需要的工具。
- 不要为了“完整”而扫描所有项目。
- 如果只需要一个项目，就不要读取其他项目。
- 如果需要具体代码，优先 search_project 定位，再 read_file 读取必要文件。
- 不要读取 .env 或任何密钥文件。

重要规则：

1. 你不能直接执行命令。
2. 你不能假装执行了工具。
3. 你不能假装读取到了尚未提供给你的项目内容。
4. 你不能自己授予自己权限。
5. 任何工具调用都必须经过中央权限层。
6. read 只能读取。
7. modify 才能修改文件。
8. git 才能 commit/push/branch。
9. dangerous 涉及删除、覆盖、reset、revert、部署、付费服务、密钥。
10. 新权限不能从旧权限自动推导。
11. 不得要求皇帝把 API Key 发给你。
12. 不得修改或泄露 API Key。
13. 不得擅自安装依赖。
14. 不得擅自扩大工具能力。

当前项目户籍：

{project_summary}

如果皇帝要求“检查”“勘察”“看看项目现在怎么样”等，
应优先制定 read-only 勘察计划。

如果需要读取项目：
明确指出：
- 项目 ID
- 使用 read_project
- 读取目的
- 只读，不修改

如果需要修改：
必须向皇帝申请 modify。

如果需要 Git：
必须单独申请 git。

如果需要危险操作：
必须单独申请 dangerous。

请使用：

【项目】
...

【圣旨理解】
...

【执行计划】
1. ...
2. ...
3. ...

【预计 Token】
输入约：...
输出约：...
总计约：...

【风险】
低 / 中 / 高 / 极高

【所需权限】
read / modify / git / dangerous

【工具】
如果需要工具，必须明确写出具体调用计划，例如：

read_project("whale-bot")

search_project("whale-bot", "active_chat")

read_file("whale-bot", "bot.py")

注意：
- 工具名称和参数必须明确。
- 不要写不存在的工具。
- 不要写 shell 命令代替工具。
- 工具仍必须经过中央权限层。

【请旨】
明确告诉皇帝需要批准什么。

注意：
这里只负责规划。
真正工具执行由 Python 中央权限层控制。

【中央工具调度协议】
你的中文奏报之后，必须额外输出一行机器可解析的工具计划，格式必须严格为：

TOOL_PLAN_JSON: {{"tools":[{{"name":"工具名","project_id":"项目ID","args":{{}}}}]}}

规则：
1. 允许使用以下工具：read_project、read_file、search_project、modify_file。
2. read_project、read_file、search_project 是只读工具。
3. modify_file 是修改工具，只有用户明确要求修改时才能提出。
4. modify_file 必须提供且只能提供：relative_path、old_text、new_text。
5. 只能针对已登记项目执行工具计划。
6. 如果本轮需要工具，必须输出 TOOL_PLAN_JSON。
7. 如果本轮不需要工具，也必须输出：
TOOL_PLAN_JSON: {{"tools":[]}}
8. TOOL_PLAN_JSON 必须单独占一行。
9. 不要把 TOOL_PLAN_JSON 放进 Markdown 代码块。
10. 工具计划中的 args 必须是 JSON 对象。
11. read_project 的 args 必须为空对象 {{}}。
12. read_file 必须提供 relative_path。
13. read_file 可以额外提供可选的 start_line、end_line，二者必须是整数。
14. 如果文件可能超过 30000 bytes，禁止生成不带 start_line/end_line 的 read_file。
15. 对大型文件，必须使用 start_line 和 end_line 分段读取；单次最多 500 行。
16. 如果尚不知道文件大小且无法确认文件很小，不要直接请求整文件读取；优先 read_project 或 search_project。
17. 如果中央层拒绝“文件过大”，下一轮必须改用 start_line/end_line，不能重复提交相同的整文件读取计划。
18. 如果用户明确要求读取指定行号范围，必须把 start_line 和 end_line 写入 read_file 的 args。
19. search_project 必须提供 keyword。
20. modify_file 不得用于 .env、.git、密钥或危险操作。
15. 修改工具仍必须经过中央权限层和皇帝明确批准，未经批准绝对不能执行。
16. 你的中文奏报可以详细解释，但程序只会执行 TOOL_PLAN_JSON 中经过中央审批的工具。

【任务判断协议】
17. 每当皇帝提出一个新的任务目标，先判断任务本身，再规划工具。
18. 必须输出一行机器可读的：
TASK_ASSESSMENT_JSON: {{"goal":"任务目标","success_criteria":["成功标准"],"complexity":"simple|normal|complex","risk":"low|medium|high|dangerous"}}
19. complexity 只表示任务规模和难度：
    - simple：简单查看、确认、解释、单点检查
    - normal：需要多步调查或修改，但范围明确
    - complex：跨项目、跨组件、目标不明确或需要较多步骤
20. risk 只表示操作风险，不表示任务难度：
    - low：只读分析、查看、检查
    - medium：有限范围修改
    - high：Git、部署、外部服务或较大范围修改
    - dangerous：删除、覆盖、reset、revert、密钥、付费操作等
21. 任务判断绝不能赋予自己任何执行权限。权限仍由中央权限层决定。
22. 成功标准必须能够通过后续真实检查验证，不能写成“尽力完成”之类无法验证的描述。

"""

    task_context = json.dumps(
        CURRENT_TASK,
        ensure_ascii=False,
        indent=2
    )

    user_message = f"""
【当前皇帝圣旨】
{user_command}

【中央任务上下文】
{task_context}

请把当前圣旨与上述任务上下文视为同一个连续任务。
如果皇帝明确是在继续上一轮任务，不要要求皇帝重复已经确认的项目、文件和目标。
如果任务上下文中已有真实工具执行结果，只能基于这些真实结果继续规划，不得臆造未读取内容。
"""

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ],
        "max_tokens": 1400,
        "stream": False
    }

    if thinking_enabled:
        payload["thinking"] = {"type": "enabled"}
        payload["reasoning_effort"] = "high"
    else:
        payload["thinking"] = {"type": "disabled"}

    data = json.dumps(
        payload,
        ensure_ascii=False
    ).encode("utf-8")

    request = urllib.request.Request(
        BASE_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=60
        ) as response:
            result = json.loads(
                response.read().decode("utf-8")
            )

    except urllib.error.HTTPError as e:
        body = e.read().decode(
            "utf-8",
            errors="replace"
        )

        raise RuntimeError(
            f"DeepSeek API HTTP {e.code}: {body[:500]}"
        )

    except urllib.error.URLError as e:
        raise RuntimeError(
            f"网络连接失败：{e.reason}"
        )

    usage = result.get("usage", {})
    total_tokens = usage.get(
        "total_tokens",
        "?"
    )

    choices = result.get("choices", [])

    if not choices:
        raise RuntimeError(
            "DeepSeek 没有返回有效回答"
        )

    content = choices[0].get(
        "message",
        {}
    ).get("content")

    if not content:
        message = choices[0].get("message", {})
        reasoning_content = message.get("reasoning_content")

        raise RuntimeError(
            "DeepSeek 返回内容为空"
            f"；message_keys={list(message.keys())}"
            f"；reasoning_content_length={len(reasoning_content or '')}"
            f"；finish_reason={choices[0].get('finish_reason')}"
        )

    print("\n" + "=" * 60)
    print("🧠 丞相奏报")
    print("=" * 60)
    print(content)
    print("=" * 60)
    print(f"实际 Token：{total_tokens}")
    print(f"模型：{result.get('model', MODEL)}")
    print(f"中央权限：{AUTHORIZED_PERMISSION or '无'}")
    print("=" * 60)

    return content


# ============================================================
# v0.3 工具调度器
# ============================================================

ALLOWED_READ_TOOLS = {
    "read_project",
    "read_file",
    "search_project",
}

ALLOWED_MODIFY_TOOLS = {
    "modify_file",
}

ALLOWED_TOOLS = ALLOWED_READ_TOOLS | ALLOWED_MODIFY_TOOLS

# 工具参数键契约：只描述"键"，不描述值类型、长度或路径。
# 注意：函数内部默认参数（read_file 的 max_bytes、search_project 的
# max_results）不是计划参数，不得出现在这里。
TOOL_ARG_SPEC = {
    "read_project": {
        "required": frozenset(),
        "optional": frozenset(),
    },
    "read_file": {
        "required": frozenset({"relative_path"}),
        "optional": frozenset({"start_line", "end_line"}),
    },
    "search_project": {
        "required": frozenset({"keyword"}),
        "optional": frozenset(),
    },
    "modify_file": {
        "required": frozenset({"relative_path", "old_text", "new_text"}),
        "optional": frozenset(),
    },
}

# 单份计划最多允许的修改类操作数：一次批准至多覆盖一次修改。
MAX_MODIFY_OPS_PER_PLAN = 1

CURRENT_TOOL_PLAN = []

# Approval record; execution binding will be added in a later patch.
PLAN_APPROVAL = None


def tool_plan_fingerprint(plan):
    import hashlib

    canonical = json.dumps(
        plan,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def plan_required_permission(plan):
    """计算整个工具计划所需的最低权限；未知工具一律拒绝。"""
    if not isinstance(plan, list) or not plan:
        raise PermissionError("拒绝：工具计划为空或格式无效。")

    required = "read"
    modify_ops = 0
    for item in plan:
        if not isinstance(item, dict):
            raise PermissionError("拒绝：计划条目格式无效。")
        name = item.get("name")

        # 工具名称必须是字符串：不可哈希类型会让随后的集合判断抛 TypeError。
        if not isinstance(name, str):
            raise PermissionError(
                f"拒绝：工具名称类型不合法（需要字符串）：{name!r}"
            )

        if name in ALLOWED_READ_TOOLS:
            continue
        if name in ALLOWED_MODIFY_TOOLS:
            modify_ops += 1
            required = "modify"
            continue
        raise PermissionError(f"拒绝未知工具：{name!r}")

    if modify_ops > MAX_MODIFY_OPS_PER_PLAN:
        raise PermissionError(
            "拒绝：单份计划最多允许 "
            f"{MAX_MODIFY_OPS_PER_PLAN} 个修改操作，实际 {modify_ops} 个。"
        )

    return required


def _check_arg_keys(name, args):
    """执行器侧的参数键契约：只检查键，不检查值。

    与解析器的键白名单保持一致，但独立实现，
    使绕过解析器的计划同样会被拒绝。
    """
    spec = TOOL_ARG_SPEC.get(name)
    if spec is None:
        raise PermissionError(f"拒绝执行未知工具：{name!r}")

    allowed = spec["required"] | spec["optional"]

    extra = set(args) - allowed
    if extra:
        raise PermissionError(
            f"工具 {name} 存在未经允许的参数：{extra}"
        )

    missing = spec["required"] - set(args)
    if missing:
        raise PermissionError(
            f"工具 {name} 缺少必需参数：{missing}"
        )


def bind_plan_approval(plan, permission, source):
    global PLAN_APPROVAL

    if permission not in PERMISSIONS:
        raise PermissionError("拒绝记录未知权限。")
    if source != "human":
        raise PermissionError("只接受人工审批来源。")
    if not isinstance(plan, list) or not plan:
        raise ValueError("拒绝绑定空计划或无效计划。")

    required = plan_required_permission(plan)
    if permission != required:
        raise PermissionError(
            f"审批权限不匹配：计划需要 {required}，"
            f"但收到的权限是 {permission}。"
        )

    fingerprint = tool_plan_fingerprint(plan)
    PLAN_APPROVAL = {
        "fingerprint": fingerprint,
        "permission": permission,
        "source": source,
        "used": False,
    }


_PRECHECK_FULL_READ_LIMIT = 30000


def _precheck_whole_file_read(project, relative_path):
    """计划层预检：整文件读取前对大文件早拒。

    这不是授权边界，真正的边界在 read_file 内。
    - safe_project_path 抛出的 PermissionError 原样冒泡，绝不吞掉。
    - 项目未登记本地 path：静默跳过预检。
    - 明确的无效路径 / 符号链接循环：安全降级为跳过。
    - 其它 OSError：不吞，原样抛出。
    """
    root = safe_project_path(project)

    if root is None:
        return

    try:
        candidate = (root / relative_path).resolve()
    except RuntimeError:
        return
    except OSError as exc:
        # PermissionError 是 OSError 子类，但 errno 不是 ELOOP，
        # 会落到下一行被重新抛出，不会被误吞。
        if getattr(exc, "errno", None) == errno.ELOOP:
            return
        raise
    except ValueError:
        return

    try:
        candidate.relative_to(root)
    except ValueError:
        return

    if not candidate.is_file():
        return

    size = candidate.stat().st_size

    if size > _PRECHECK_FULL_READ_LIMIT:
        raise PermissionError(
            f"文件过大：{relative_path} ({size} bytes)。"
            f"超过 {_PRECHECK_FULL_READ_LIMIT} bytes，"
            "必须使用 start_line/end_line 分段读取。"
        )


def parse_tool_plan(content, allowed_tools=None):
    global CURRENT_TOOL_PLAN
    CURRENT_TOOL_PLAN = []

    allowed_names = (
        ALLOWED_TOOLS if allowed_tools is None else set(allowed_tools)
    )

    line = None

    for raw in content.splitlines():
        raw = raw.strip()
        if raw.startswith("TOOL_PLAN_JSON:"):
            line = raw[len("TOOL_PLAN_JSON:"):].strip()
            break

    if line is None:
        raise ValueError(
            "丞相没有提供 TOOL_PLAN_JSON，本轮拒绝执行。"
        )

    try:
        data = json.loads(line)
    except json.JSONDecodeError as e:
        raise ValueError(f"工具计划 JSON 错误：{e}")

    # 顶层必须是 JSON 对象，否则 .get() 会抛 AttributeError。
    if not isinstance(data, dict):
        raise ValueError("工具计划顶层必须是 JSON 对象。")

    tools = data.get("tools", [])

    if not isinstance(tools, list):
        raise ValueError("tools 必须是数组。")

    if len(tools) > 20:
        raise ValueError("单轮工具调用超过 20 个，已拒绝。")

    projects = load_projects()
    validated = []

    for item in tools:
        if not isinstance(item, dict):
            raise ValueError("工具计划存在无效项目。")

        name = item.get("name")
        project_id = item.get("project_id")
        args = item.get("args", {})

        # 类型检查必须前移：先确认 name 是字符串、args 是字典，
        # 之后才允许集合成员判断、args.keys() 与字段访问。
        if not isinstance(name, str):
            raise ValueError("工具计划的 name 必须是字符串。")

        if not isinstance(args, dict):
            raise ValueError("工具参数 args 必须是 JSON 对象。")

        if not isinstance(project_id, str):
            raise ValueError("工具计划的 project_id 必须是字符串。")

        if name not in ALLOWED_TOOLS:
            raise PermissionError(f"未知工具：{name}")

        if name not in allowed_names:
            raise PermissionError(
                f"本轮计划不允许使用该工具：{name}"
                "（当前阶段仅允许只读工具）"
            )

        # 参数键集合唯一来源：parser 与 executor 共用 TOOL_ARG_SPEC。
        spec = TOOL_ARG_SPEC[name]
        allowed = spec["required"] | spec["optional"]

        if name == "modify_file":
            if set(args.keys()) != spec["required"]:
                raise PermissionError(
                    "modify_file 参数必须且只能是：relative_path、old_text、new_text"
                )
        elif name in ALLOWED_READ_TOOLS:
            pass

        if project_id not in projects:
            raise PermissionError(
                f"项目未登记：{project_id}"
            )

        if name == "read_project":
            pass

        elif name == "read_file":
            if "relative_path" not in args:
                raise ValueError("read_file 缺少 relative_path")

            _validate_relative_path(args["relative_path"])

            # 中央硬规则：大文件禁止整文件读取，必须使用行范围。
            if "start_line" not in args and "end_line" not in args:
                project = projects.get(project_id)
                if project:
                    _precheck_whole_file_read(
                        project, args["relative_path"]
                    )

            if "start_line" in args:
                _validate_line_number("start_line", args["start_line"])

            if "end_line" in args:
                _validate_line_number("end_line", args["end_line"])

            if (
                "start_line" in args
                and "end_line" in args
                and args["end_line"] < args["start_line"]
            ):
                raise ValueError(
                    "end_line 不能小于 start_line"
                )

        elif name == "modify_file":
            _validate_relative_path(args["relative_path"])
            _validate_text_arg(
                "old_text", args["old_text"], MAX_OLD_TEXT_CHARS
            )
            _validate_text_arg(
                "new_text", args["new_text"], MAX_NEW_TEXT_CHARS
            )

            if args["old_text"] == "":
                raise PermissionError(
                    "禁止空 old_text 修改，防止误插入。"
                )

        elif name == "search_project":
            if "keyword" not in args:
                raise ValueError("search_project 缺少 keyword")

            _validate_text_arg(
                "keyword", args["keyword"], MAX_SEARCH_KEYWORD_CHARS
            )

            if not args["keyword"].strip():
                raise ValueError("搜索关键词不能为空。")

        else:
            raise PermissionError(f"拒绝工具：{name}")

        extra = set(args) - allowed
        if extra:
            raise PermissionError(
                f"工具 {name} 存在未经允许的参数：{extra}"
            )

        validated.append({
            "name": name,
            "project_id": project_id,
            "args": args
        })

    CURRENT_TOOL_PLAN = validated
    return validated


def show_tool_plan(plan):
    print()
    print("=" * 60)
    print("📜 中央工具调度单")
    print("=" * 60)

    if not plan:
        print("本轮无需工具。")
    else:
        read_count = 0
        modify_count = 0

        for i, item in enumerate(plan, 1):
            name = item["name"]

            if name in ALLOWED_READ_TOOLS:
                tag = "[只读]"
                read_count += 1
            else:
                tag = "[修改]"
                modify_count += 1

            print(
                f"{i}. {tag} {name}("
                f"{item['project_id']}, "
                f"{json.dumps(item['args'], ensure_ascii=False)})"
            )

            if name in ALLOWED_MODIFY_TOOLS:
                target = item["args"].get("relative_path", "?")
                print(
                    f"    → 将先创建独立备份，再以原子替换写入新内容：{target}"
                )

        print("-" * 60)
        print(
            f"合计 {len(plan)} 项："
            f"只读 {read_count} 项，修改 {modify_count} 项"
        )

    print("=" * 60)



def _make_backup_candidate(target, attempt=0):
    """生成唯一备份候选路径；每次调用都取新的时间戳。

    文件名形如：
        bot.py.20250615T143012123456.before_chengxiang_modify.bak
        bot.py.20250615T143012123456-1.before_chengxiang_modify.bak
    后缀固定为 .bak，命中 .gitignore 中已有的 *.bak 规则。
    """
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S%f")
    discriminator = "" if attempt == 0 else f"-{attempt}"
    return target.with_name(
        f"{target.name}.{stamp}{discriminator}"
        ".before_chengxiang_modify.bak"
    )


def _make_partial_candidate(official_path):
    """把正式备份路径映射为同名的 .partial 半成品路径。

    例：a.txt.<stamp>.before_chengxiang_modify.bak
     →  a.txt.<stamp>.before_chengxiang_modify.partial
    """
    name = official_path.name
    if name.endswith(".bak"):
        name = name[:-len(".bak")]
    return official_path.with_name(name + ".partial")


def _abandon_partial_backup(handle, backup):
    """保留半成品备份：只关闭句柄并告警，绝不删除。

    设计理由：POSIX 没有"按 inode 删除"的原子原语，任何按名字删除
    都可能删到被替换进来的其它文件。因此本函数不存在任何删除操作。

    handle 允许为 None（备份已发布、发布失败等阶段无可关闭句柄）。
    """
    closed = True
    if handle is not None:
        try:
            handle.close()
        except OSError:
            closed = False

    print(
        "⚠️ 本次备份未完成，半成品已保留（不做自动清理）："
        f"{backup}"
    )
    return "closed" if closed else "close_failed"


class BackupPublishError(RuntimeError):
    """备份发布失败：正式 .bak 未被创建，目标文件未被修改。"""


class BackupDurabilityError(BackupPublishError):
    """renameat2 已成功，但父目录 fsync 失败。

    此时正式 .bak 可能已经存在（内容正确），只是"断电后是否仍存在"
    无法确认。调用方不得删除它，也不得声称备份不存在。
    """


# Linux renameat2 标志位与 AT_FDCWD。
RENAME_NOREPLACE = 1
AT_FDCWD = -100

# 这些 errno 表示"原语或权限不可用"，必须 fail-closed，禁止降级。
_RENAMEAT2_FATAL_ERRNOS = frozenset(
    code for code in (
        getattr(errno, "ENOSYS", None),
        getattr(errno, "EINVAL", None),
        getattr(errno, "EOPNOTSUPP", None),
        getattr(errno, "EPERM", None),
        getattr(errno, "EACCES", None),
    ) if code is not None
)

_renameat2_fn = None
_renameat2_loaded = False


def _load_renameat2():
    """返回 libc 的 renameat2 调用；不可用时返回 None（调用方必须 fail-closed）。"""
    global _renameat2_fn, _renameat2_loaded

    if _renameat2_loaded:
        return _renameat2_fn

    _renameat2_loaded = True

    if not hasattr(os, "uname") or os.uname().sysname != "Linux":
        _renameat2_fn = None
        return None

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        fn = libc.renameat2
        fn.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        fn.restype = ctypes.c_int
        _renameat2_fn = fn
    except (OSError, AttributeError):
        _renameat2_fn = None

    return _renameat2_fn


def _fsync_directory(directory, published_path):
    """对目录执行 fsync，尽可能保证目录项持久化。

    失败即抛 BackupDurabilityError：rename 已经成功，正式 .bak 可能已存在，
    不得删除该文件，也不得声称备份不存在。
    """
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)

    try:
        fd = os.open(directory, flags)
    except OSError as exc:
        raise BackupDurabilityError(
            f"备份可能已发布为 {published_path}，但父目录无法打开做 fsync，"
            f"持久性未确认：{directory}；{exc}"
        ) from exc

    try:
        os.fsync(fd)
    except OSError as exc:
        raise BackupDurabilityError(
            f"备份可能已发布为 {published_path}，但父目录 fsync 失败，"
            f"持久性未确认：{directory}；{exc}"
        ) from exc
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _verify_partial_identity(partial, identity):
    """发布前复核：.partial 必须仍是本次创建并写入的那个普通文件。

    使用 lstat，绝不跟随符号链接。任一条件不满足即 fail-closed：
    不发布正式 .bak、不修改目标文件、不删除被替换的对象。
    """
    if identity is None:
        raise BackupPublishError(
            "备份发布失败（阶段：verify）：缺少 .partial 的身份记录，"
            f"拒绝发布；现场保留：{partial}"
        )

    try:
        info = os.lstat(partial)
    except FileNotFoundError as exc:
        raise BackupPublishError(
            "备份发布失败（阶段：verify）：.partial 已不存在，"
            f"拒绝发布；现场保留：{partial}"
        ) from exc
    except OSError as exc:
        raise BackupPublishError(
            "备份发布失败（阶段：verify）：无法检查 .partial 状态，"
            f"拒绝发布；现场保留：{partial}；{exc}"
        ) from exc

    if stat.S_ISLNK(info.st_mode):
        raise BackupPublishError(
            "备份发布失败（阶段：verify）：.partial 已变成符号链接，"
            f"拒绝发布（不跟随链接）；现场保留：{partial}"
        )

    if not stat.S_ISREG(info.st_mode):
        raise BackupPublishError(
            "备份发布失败（阶段：verify）：.partial 不再是普通文件，"
            f"拒绝发布；现场保留：{partial}"
        )

    actual = (info.st_dev, info.st_ino)

    if actual != identity:
        raise BackupPublishError(
            "备份发布失败（阶段：verify）：.partial 已被替换"
            f"（期望 inode {identity}，实际 {actual}），"
            f"拒绝发布；现场保留：{partial}"
        )


def _publish_backup(partial, target):
    """用 Linux renameat2(RENAME_NOREPLACE) 把 .partial 严格发布为正式 .bak。

    保证分层：
    - "原子不覆盖"：由 RENAME_NOREPLACE 保证；目标已存在时内核返回 EEXIST，
      本函数换下一个候选名重试，绝不覆盖。
    - "断电后持久化"：由发布成功后的父目录 fsync 尽力保证；失败时抛
      BackupDurabilityError，如实报告"可能已发布、持久性未确认"。
    这两个是不同的保证，不可混为一谈。

    原语或权限不可用（非 Linux / libc 无符号 / ENOSYS / EINVAL /
    EOPNOTSUPP / EPERM / EACCES）时一律 fail-closed，绝不降级为
    os.rename / os.replace。
    """
    fn = _load_renameat2()

    if fn is None:
        raise BackupPublishError(
            "备份发布失败（阶段：publish）：当前平台不提供 "
            "renameat2(RENAME_NOREPLACE)，拒绝发布；"
            f"半成品已保留：{partial}"
        )

    for attempt in range(MAX_BACKUP_ATTEMPTS):
        official = _make_backup_candidate(target, attempt)

        ctypes.set_errno(0)
        rc = fn(
            AT_FDCWD,
            os.fsencode(str(partial)),
            AT_FDCWD,
            os.fsencode(str(official)),
            RENAME_NOREPLACE,
        )

        if rc == 0:
            _fsync_directory(official.parent, official)
            return official

        err = ctypes.get_errno()

        if err == errno.EEXIST:
            continue

        code = errno.errorcode.get(err, str(err))

        if err in _RENAMEAT2_FATAL_ERRNOS:
            raise BackupPublishError(
                "备份发布失败（阶段：publish）：renameat2 返回 "
                f"{code}，说明原语或权限不可用，拒绝降级；"
                f"半成品已保留：{partial}"
            )

        raise BackupPublishError(
            "备份发布失败（阶段：publish）：renameat2 返回 "
            f"{code}；半成品已保留：{partial}"
        )

    raise BackupPublishError(
        "备份发布失败（阶段：publish）："
        f"{MAX_BACKUP_ATTEMPTS} 个候选备份名均已被占用；"
        f"半成品已保留：{partial}"
    )


# 只有 ELOOP 表示"最终组件是符号链接 / 符号链接循环"。
# 其它 errno（例如 EMLINK）必须走通用错误路径，不得误报为符号链接拒绝。
_OPEN_NOFOLLOW_ERRNOS = frozenset(
    code for code in (
        getattr(errno, "ELOOP", None),
    ) if code is not None
)


def _open_target_no_follow(target):
    """以 O_NOFOLLOW 打开目标文件，拒绝最终路径组件是符号链接。

    保护范围仅限**最终路径组件**：父目录组件中的符号链接由调用方的
    "解析父目录 + target.relative_to(root)" 负责，不在本函数保证之内。

    平台不提供 O_NOFOLLOW 时一律 fail-closed，绝不静默降级为普通打开。
    最终组件是符号链接（或存在符号链接循环）时，内核返回 ELOOP，
    这里统一转换为项目既有的安全拒绝错误 PermissionError。
    """
    nofollow = getattr(os, "O_NOFOLLOW", None)

    if nofollow is None:
        raise PermissionError(
            "当前平台不支持 O_NOFOLLOW，无法安全打开目标文件，"
            "拒绝修改（fail-closed）。"
        )

    try:
        return os.open(target, os.O_RDONLY | nofollow)
    except OSError as exc:
        if getattr(exc, "errno", None) in _OPEN_NOFOLLOW_ERRNOS:
            raise PermissionError(
                "拒绝修改：目标文件的最终路径组件是符号链接，"
                f"或存在符号链接循环：{target}"
            ) from exc
        raise


class TargetLockBusy(RuntimeError):
    """同一目标文件已被另一个丞相实例锁定，本次修改放弃。"""


class ModifyConflictError(RuntimeError):
    """目标文件在处理过程中被外部替换，拒绝覆盖，已停止修改。"""


def _lock_dir():
    """锁目录位于仓库之外，随 HOME 变化（便于测试隔离）。"""
    return Path.home() / ".local" / "state" / "chengxiang" / "locks"


def _target_lock_path(target):
    digest = hashlib.sha256(str(target).encode("utf-8")).hexdigest()
    return _lock_dir() / f"{digest}.lock"


def _acquire_target_lock(target):
    """获取目标文件级排他锁（协作锁，跨丞相实例有效）。

    非阻塞：拿不到立即失败，避免用户长时间卡住。
    """
    directory = _lock_dir()

    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    except OSError as exc:
        raise RuntimeError(f"无法创建锁目录 {directory}：{exc}") from exc

    path = _target_lock_path(target)
    flags = os.O_RDWR | os.O_CREAT
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is not None:
        flags |= nofollow
    cloexec = getattr(os, "O_CLOEXEC", None)
    if cloexec is not None:
        flags |= cloexec

    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise RuntimeError(f"无法打开目标锁文件：{exc}") from exc

    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise TargetLockBusy(
            "目标文件正被另一个丞相实例修改，本次修改已放弃："
            f"{target}"
        )

    return fd


def _release_target_lock(fd):
    """释放目标锁；任何失败都不得掩盖调用方的异常。"""
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(fd)
    except OSError:
        pass


def modify_file(project_id, relative_path, old_text, new_text):
    """
    中央 modify 兵符：
    - 必须拥有 modify 权限
    - 只能操作已登记项目
    - 禁止 .env / 密钥 / Git 文件
    - 拒绝 setuid/setgid 特殊权限文件
    - 修改前自动创建独立备份，成功后保留
    - 必须精确匹配 old_text，防止误改
    - 全程按字节读写，不做编码或换行转换
    """
    require_permission("modify")

    # 参数校验必须在任何文件系统访问之前完成。
    _validate_relative_path(relative_path)

    if not isinstance(old_text, str) or not isinstance(new_text, str):
        raise PermissionError("old_text 与 new_text 必须是字符串。")

    _validate_text_arg("old_text", old_text, MAX_OLD_TEXT_CHARS)
    _validate_text_arg("new_text", new_text, MAX_NEW_TEXT_CHARS)

    if old_text == "":
        raise PermissionError("禁止空 old_text 修改，防止误插入。")

    try:
        get_registered_project(project_id)
    except ValueError as exc:
        raise PermissionError(f"未知项目：{project_id}") from exc

    from pathlib import PurePosixPath, PureWindowsPath

    normalized = relative_path.replace("\\", "/").strip()
    posix_path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(relative_path)

    if (
        posix_path.is_absolute()
        or windows_path.is_absolute()
        or windows_path.drive
    ):
        raise PermissionError("只允许使用项目内相对路径。")

    if ".." in posix_path.parts or ".." in windows_path.parts:
        raise PermissionError("禁止使用 .. 越界访问项目目录。")

    forbidden_components = set(FORBIDDEN_READ_NAMES) | {".git"}

    for component in posix_path.parts:
        name = component.lower()

        if name in forbidden_components:
            raise PermissionError(
                f"中央禁止修改敏感路径：{relative_path}"
            )

        if any(
            name.endswith(suffix)
            for suffix in FORBIDDEN_READ_SUFFIXES
        ):
            raise PermissionError(
                f"中央禁止修改敏感路径：{relative_path}"
            )

    try:
        root = get_local_project_root(project_id)
    except ValueError as exc:
        raise PermissionError(
            f"项目 {project_id} 没有可用的本地工作区：{exc}"
        ) from exc
    # 只解析父目录，保留最终组件的原始名字：
    # 若把最终组件也 resolve 掉，"它本身是符号链接"这一事实会被抹去，
    # O_NOFOLLOW 就无从判断。父目录的解析仍用于 relative_to 越界防护。
    parent = (root / normalized).parent.resolve()
    target = parent / Path(normalized).name

    try:
        target.relative_to(root)
    except ValueError:
        raise PermissionError("目标文件越出项目目录。")

    # 对解析符号链接后的真实路径再次检查敏感组件。
    resolved_relative = target.relative_to(root)
    for component in resolved_relative.parts:
        name = component.lower()
        if name in forbidden_components or any(
            name.endswith(suffix)
            for suffix in FORBIDDEN_READ_SUFFIXES
        ):
            raise PermissionError(
                f"中央禁止修改敏感目标：{relative_path}"
            )

    # 从这里开始进入受锁保护的主体：读取、备份、复核、替换全部串行化。
    lock_fd = _acquire_target_lock(target)
    try:
        return _modify_file_locked(
            target, project_id, relative_path, old_text, new_text
        )
    finally:
        _release_target_lock(lock_fd)


def _modify_file_locked(target, project_id, relative_path, old_text, new_text):
    """在已持有目标锁的前提下执行修改主体。"""
    # 用 lstat 检查最终组件本身：符号链接在这里就被拒绝（不跟随），
    # 而不是先跟随、再判断目标是否为普通文件。
    try:
        target_lstat = os.lstat(target)
    except FileNotFoundError:
        raise FileNotFoundError(f"目标文件不存在：{relative_path}")

    if stat.S_ISLNK(target_lstat.st_mode):
        raise PermissionError(
            "拒绝修改：目标文件本身是符号链接（不做跟随）："
            f"{relative_path}"
        )

    if not stat.S_ISREG(target_lstat.st_mode):
        raise ValueError(f"目标不是普通文件：{relative_path}")

    # 用同一个已打开的描述符完成"身份 / 类型 / 特殊权限 / 大小 / 内容"检查，
    # 避免 stat 与 read 之间的竞态（检查的对象必须就是被读取的对象）。
    try:
        source_fd = _open_target_no_follow(target)
    except PermissionError:
        raise
    except OSError as exc:
        raise RuntimeError(
            f"打开目标文件失败（阶段：open）：{relative_path}；{exc}"
        ) from exc

    try:
        target_stat = os.fstat(source_fd)

        if not stat.S_ISREG(target_stat.st_mode):
            raise ValueError(f"目标不是普通文件：{relative_path}")

        # 特殊权限检查：必须早于备份创建与文件读取。
        if target_stat.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise PermissionError(
                "拒绝修改带有 setuid/setgid 特殊权限的文件："
                f"{relative_path}"
            )

        if target_stat.st_size > MAX_MODIFY_FILE_BYTES:
            raise ValueError(
                f"文件过大：{relative_path} ({target_stat.st_size} bytes)，"
                f"超过修改上限 {MAX_MODIFY_FILE_BYTES} bytes，拒绝修改。"
            )

        # 有界读取：最多读 MAX_MODIFY_FILE_BYTES + 1 字节，
        # 即使文件在 fstat 之后继续增长也不会突破上限。
        original_bytes = _read_bounded(
            source_fd, MAX_MODIFY_FILE_BYTES + 1
        )
    except BaseException:
        # 有异常在飞：关闭失败不得覆盖它，原始异常原样上抛。
        try:
            os.close(source_fd)
        except OSError:
            pass
        raise
    else:
        os.close(source_fd)

    if len(original_bytes) > MAX_MODIFY_FILE_BYTES:
        raise ValueError(
            f"文件过大：{relative_path}，读取量已超过修改上限 "
            f"{MAX_MODIFY_FILE_BYTES} bytes，拒绝修改。"
        )

    original_mode = stat.S_IMODE(target_stat.st_mode)
    # 备份权限只保留 rwx，清除 setuid/setgid/sticky。
    # 按位与只能清除位，因此备份权限恒不宽于原文件。
    backup_mode = original_mode & 0o777

    # 严格 UTF-8 解码，避免按 locale 静默重编码。
    try:
        content = original_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"拒绝修改非 UTF-8 文本文件：{relative_path}"
            f"（偏移 {exc.start} 处解码失败）。"
        ) from exc

    # 记录读取时的字节指纹，用于发现并发修改。
    original_hash = hashlib.sha256(original_bytes).hexdigest()

    count = content.count(old_text)

    if count == 0:
        raise ValueError("未找到精确匹配内容，未修改文件。")

    if count > 1:
        raise ValueError(
            f"找到 {count} 处匹配，无法确认唯一修改位置，未修改文件。"
        )

    # 独立备份，分两阶段：
    #   阶段一：以 .partial 名义独占创建并完整写入；失败时绝不冒充正式备份。
    #   阶段二：renameat2(RENAME_NOREPLACE) 严格发布为正式 .bak；
    #           目标已存在时内核返回 EEXIST，换名重试，绝不覆盖。
    backup = None
    partial = None
    partial_handle = None

    for attempt in range(MAX_BACKUP_ATTEMPTS):
        candidate = _make_backup_candidate(target, attempt)
        partial_candidate = _make_partial_candidate(candidate)
        try:
            partial_handle = partial_candidate.open("xb")
        except FileExistsError:
            continue
        backup = candidate
        partial = partial_candidate
        break

    if partial_handle is None:
        raise RuntimeError(
            f"连续 {MAX_BACKUP_ATTEMPTS} 次无法生成唯一 .partial 备份文件名，"
            "未修改任何文件。"
        )

    # backup_ready 之后，正式备份已发布，不存在任何删除它的路径。
    backup_ready = False
    partial_identity = None
    try:
        # 记录本次创建的 .partial 身份，发布前必须仍然是它。
        created_stat = os.fstat(partial_handle.fileno())
        partial_identity = (created_stat.st_dev, created_stat.st_ino)
        # 先定权限再写内容，消除"宽权限 + 已含内容"的时间窗。
        os.fchmod(partial_handle.fileno(), backup_mode)
        partial_handle.write(original_bytes)
        partial_handle.flush()
        os.fsync(partial_handle.fileno())
    except BaseException as exc:
        # 不自动删除半成品：按名字删除可能删到被替换进来的文件。
        status = _abandon_partial_backup(partial_handle, partial)
        if hasattr(exc, "add_note"):
            try:
                exc.add_note(
                    "备份写入阶段失败，半成品以 .partial 保留"
                    "（未发布为正式备份）："
                    f"{partial}（状态：{status}）"
                )
            except Exception:
                pass
        raise
    else:
        partial_handle.close()

    # 阶段二：先复核 .partial 身份，再用 renameat2(RENAME_NOREPLACE) 发布。
    try:
        _verify_partial_identity(partial, partial_identity)
        official = _publish_backup(partial, target)
    except BackupDurabilityError:
        # rename 已成功：正式 .bak 可能已存在，只是持久性未确认。
        # 不删除、不否认，原样上报，由调用方决定。
        raise
    except BackupPublishError:
        _abandon_partial_backup(None, partial)
        raise

    backup = official
    backup_ready = True

    new_content = content.replace(old_text, new_text, 1)

    # 防御性不变量：没有已发布的完整备份就绝不进入替换阶段。
    if not backup_ready:
        raise RuntimeError(
            "内部不变量被破坏：缺少已发布的完整备份，拒绝替换目标文件。"
        )

    # 同目录临时文件：完整写入后再替换正式文件。
    temp_path = None

    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=".chengxiang_tmp_",
            suffix=".tmp",
            dir=str(target.parent),
        )
        temp_path = Path(temp_name)

        # closefd=False：fd 的所有权始终留在本函数；文件对象只负责
        # 缓冲写入 / flush / fsync，绝不代劳关闭，因此不依赖
        # os.fdopen 失败时是否已由内部对象关闭（属实现细节）。
        try:
            with os.fdopen(fd, "wb", closefd=False) as temp_file:
                temp_file.write(new_content.encode("utf-8"))
                temp_file.flush()
                os.fsync(temp_file.fileno())
        except BaseException:
            # 有异常在飞：关闭失败不得覆盖原始异常。
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        else:
            os.close(fd)          # 正常路径：关闭失败必须向上传播

        os.chmod(temp_path, original_mode)

        # 替换前按字节复核；若文件已变化（含超出读取上限），拒绝覆盖。
        check_fd = _open_target_no_follow(target)
        try:
            # 身份复核：内容相同但 inode 已变，说明文件被换过（原子保存），
            # 单靠 SHA-256 无法发现这种替换。
            check_stat = os.fstat(check_fd)
            if (check_stat.st_dev, check_stat.st_ino) != (
                target_stat.st_dev,
                target_stat.st_ino,
            ):
                raise ModifyConflictError(
                    "安全停止：目标文件在读取后被替换（inode 变化），"
                    f"拒绝覆盖。完整备份已保留：{backup}"
                )
            current_bytes = _read_bounded(
                check_fd, MAX_MODIFY_FILE_BYTES + 1
            )
        except BaseException:
            # 有异常在飞：关闭失败不得覆盖它，原始异常原样上抛。
            try:
                os.close(check_fd)
            except OSError:
                pass
            raise
        else:
            os.close(check_fd)

        if (
            len(current_bytes) > MAX_MODIFY_FILE_BYTES
            or hashlib.sha256(current_bytes).hexdigest() != original_hash
        ):
            raise RuntimeError(
                "安全停止：目标文件在读取后发生变化，拒绝覆盖。"
                f"完整备份已保留：{backup}"
            )

        os.replace(temp_path, target)
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink()
            except OSError:
                pass

    return {
        "project": project_id,
        "file": str(target),
        "backup": str(backup),
        "replaced": 1,
    }


class ToolPlanExecutionError(RuntimeError):
    """执行计划中途失败，携带已完成、失败及未执行项目的报告。"""

    def __init__(self, message, report, failed_index):
        super().__init__(message)
        self.report = report
        self.failed_index = failed_index

def print_tool_plan_report(report):
    """显示工具计划中已完成、失败和未执行的项目。"""
    labels = {
        "success": "已完成",
        "failed": "失败",
        "not_executed": "未执行",
    }

    print()
    print("=" * 60)
    print("⚠️ 工具计划执行报告：失败后已停止")

    for item in report:
        status = item.get("status", "unknown")
        label = labels.get(status, status)
        index = item.get("index", "?")
        tool = item.get("tool", "未知工具")
        project = item.get("project", "未知项目")

        print()
        print(f"[{label}] 第 {index} 项：{tool}（项目：{project}）")

        if status == "success":
            summary = json.dumps(
                item.get("result"),
                ensure_ascii=False,
                default=repr,
            )
            if len(summary) > 500:
                summary = summary[:500] + "……（显示已截断）"
            print("结果摘要：" + summary)

        elif status == "failed":
            print("错误：" + str(item.get("error", "未知错误")))
            print(
                "注意：" + str(
                    item.get(
                        "verification",
                        "需核查是否产生部分副作用",
                    )
                )
            )

        elif item.get("reason"):
            print("原因：" + str(item["reason"]))

        if item.get("audit_warning"):
            print("⚠️ 审计警告：" + str(item["audit_warning"]))

    print()
    print("安全策略：不自动重试、不自动回滚；后续项目未执行。")
    print("=" * 60)




def execute_tool_plan(plan):
    if STATE != "AUTHORIZED":
        raise PermissionError("未进入 AUTHORIZED 状态，禁止执行。")

    approval = PLAN_APPROVAL
    if not isinstance(approval, dict) or approval.get("used") is not False:
        raise PermissionError("拒绝执行：没有有效的、未使用的计划批准记录。")

    approval["used"] = True

    if not isinstance(plan, list) or not plan:
        raise PermissionError("拒绝执行：计划为空或格式无效。")

    # 与解析器保持一致的数量上限；位于审计与任何工具分发之前。
    if len(plan) > 20:
        raise PermissionError("拒绝执行：单轮工具超过 20 个。")

    try:
        fingerprint = tool_plan_fingerprint(plan)
    except (TypeError, ValueError):
        raise PermissionError("拒绝执行：无法验证计划指纹。")

    if fingerprint != approval.get("fingerprint"):
        raise PermissionError("拒绝执行：计划与获批内容不一致。")

    approved_permission = approval.get("permission")
    if approved_permission not in PERMISSIONS:
        raise PermissionError("拒绝执行：批准记录中的权限无效。")
    if AUTHORIZED_PERMISSION != approved_permission:
        raise PermissionError("拒绝执行：当前权限与批准记录不一致。")

    required = plan_required_permission(plan)
    if approved_permission != required:
        raise PermissionError(
            f"拒绝执行：计划需要 {required}，"
            f"但批准权限为 {approved_permission}。"
        )

    for item in plan:
        if not isinstance(item, dict):
            raise PermissionError("拒绝执行：计划条目格式无效。")
        if not {"name", "project_id", "args"}.issubset(item):
            raise PermissionError("拒绝执行：计划条目缺少必要字段。")

        project_id = item["project_id"]
        if not isinstance(project_id, str):
            raise PermissionError(
                "拒绝执行：project_id 类型不合法（需要字符串）："
                f"{project_id!r}"
            )

        name = item["name"]
        if name in ALLOWED_READ_TOOLS:
            required = "read"
        elif name in ALLOWED_MODIFY_TOOLS:
            required = "modify"
        else:
            raise PermissionError(f"拒绝执行未知工具：{name!r}")

        if not isinstance(item["args"], dict):
            raise PermissionError("拒绝执行：工具参数必须为对象。")

        _check_arg_keys(name, item["args"])

        if permission_level(approved_permission) < permission_level(required):
            raise PermissionError(
                f"拒绝执行：批准权限不足，工具 {name!r} 需要 {required}。"
            )

    source_name = approval.get("source", "human")
    try:
        audit_event(
            "execution_started",
            permission=approved_permission,
            source=source_name,
            status="started",
        )
    except Exception as exc:
        # 审计失败必须终止：此时尚未分发任何工具，保持 fail-closed。
        raise RuntimeError(
            f"执行前审计写入失败，已终止本次执行：{type(exc).__name__}"
        ) from exc

    results = []

    def success_report():
        return [
            {
                "index": i,
                "tool": done["tool"],
                "project": done["project"],
                "status": "success",
                "result": done["result"],
            }
            for i, done in enumerate(results, 1)
        ]

    def record_pending(first_index):
        for pending_index, pending in enumerate(plan[first_index:], first_index + 1):
            row = {
                "index": pending_index,
                "tool": pending["name"],
                "project": pending["project_id"],
                "status": "not_executed",
                "reason": "前一项发生错误或审计故障，已停止后续操作",
            }
            try:
                audit_event(
                    "tool_not_executed",
                    project_id=pending["project_id"],
                    permission=approved_permission,
                    source=source_name,
                    tool=pending["name"],
                    status="not_executed",
                    index=pending_index,
                    reason="previous_item_stopped",
                )
            except Exception as audit_exc:
                row["audit_warning"] = (
                    "未执行事件未能写入审计日志："
                    + type(audit_exc).__name__
                )
            report.append(row)

    for index, item in enumerate(plan, 1):
        name = item["name"]
        project_id = item["project_id"]
        args = item["args"]

        try:
            if name in ALLOWED_READ_TOOLS:
                require_permission("read")
            elif name in ALLOWED_MODIFY_TOOLS:
                require_permission("modify")
            else:
                raise PermissionError(f"中央拒绝执行未知工具：{name}")

            if name == "read_project":
                result = read_project(project_id)
            elif name == "read_file":
                result = read_file(
                    project_id, args["relative_path"],
                    args.get("start_line"), args.get("end_line")
                )
            elif name == "search_project":
                result = search_project(project_id, args["keyword"])
            elif name == "modify_file":
                result = modify_file(
                    project_id, args["relative_path"],
                    args["old_text"], args["new_text"]
                )
            else:
                raise PermissionError(f"中央拒绝执行工具：{name}")

        except Exception as exc:
            report = success_report()
            failed_row = {
                "index": index,
                "tool": name,
                "project": project_id,
                "status": "failed",
                "error": f"{type(exc).__name__}: {exc}",
                "verification": "需核查是否产生部分副作用",
            }
            try:
                audit_event(
                    "tool_failed",
                    project_id=project_id,
                    permission=approved_permission,
                    source=source_name,
                    tool=name,
                    status="failed",
                    index=index,
                    error_type=type(exc).__name__,
                )
            except Exception as audit_exc:
                failed_row["audit_warning"] = (
                    "失败事件未能写入审计日志："
                    + type(audit_exc).__name__
                )
            report.append(failed_row)
            record_pending(index)
            try:
                audit_event(
                    "execution_finished",
                    permission=approved_permission,
                    source=source_name,
                    status="failed",
                    reason="tool_failed",
                )
            except Exception as audit_exc:
                failed_row["audit_warning"] = (
                    failed_row.get("audit_warning", "")
                    + "；结束事件写入失败："
                    + type(audit_exc).__name__
                ).strip("；")
            raise ToolPlanExecutionError(
                f"计划第 {index} 项执行失败，后续操作已停止。",
                report, index,
            ) from exc

        results.append({
            "tool": name,
            "project": project_id,
            "result": result,
        })

        try:
            audit_event(
                "tool_succeeded",
                project_id=project_id,
                permission=approved_permission,
                source=source_name,
                tool=name,
                status="success",
                index=index,
            )
        except Exception as audit_exc:
            report = success_report()
            report[-1]["audit_warning"] = (
                "工具已执行成功，但成功事件未能写入审计日志："
                + type(audit_exc).__name__
                + "。没有重试该工具。"
            )
            record_pending(index)
            try:
                audit_event(
                    "execution_finished",
                    permission=approved_permission,
                    source=source_name,
                    status="audit_failed",
                    reason="tool_succeeded_event_write_failed",
                )
            except Exception:
                pass
            raise ToolPlanExecutionError(
                f"第 {index} 项已成功，但审计记录失败；后续操作已停止。",
                report, index,
            ) from audit_exc

    try:
        audit_event(
            "execution_finished",
            permission=approved_permission,
            source=source_name,
            status="success",
        )
    except Exception as audit_exc:
        report = success_report()
        report[-1]["audit_warning"] = (
            "所有计划项目均已执行完成，但结束事件未能写入审计日志："
            + type(audit_exc).__name__
            + "。没有重试任何工具。"
        )
        raise ToolPlanExecutionError(
            "计划已执行完成，但审计结束记录失败。",
            report, len(plan),
        ) from audit_exc

    return results



# ============================================================
# 人类审批入口
# ============================================================

def _normalize_approval(text):
    """手机输入常带中文标点，统一去掉首尾空白与标点再判断。"""
    return str(text or "").strip().strip("。.！!？?，,、；;：: \t")


def approval_flow(prefilled=None):
    """
    当前版本仍采用人工批准。
    不允许 DeepSeek 自己决定批准。

    prefilled：主循环已经收到的答复（如「准奏 read」）。
    非空时直接采用，不再重复询问。
    """
    global STATE, CURRENT_TOOL_PLAN

    answer = _normalize_approval(prefilled)

    if not answer:
        print()
        print("🔐 中央审批")
        print("输入：")
        print("  准奏 read")
        print("  准奏 modify")
        print("  驳回")
        print()

        answer = _normalize_approval(input("👑 圣裁：> "))

    if answer == "退出":
        clear_authorization()
        CURRENT_TOOL_PLAN = []
        STATE = "EXIT"
        print("👋 丞相府关闭。")
        reset_current_task()
        return "退出"

    if answer == "驳回":
        try:
            audit_event("approval_rejected", source="human", status="rejected")
        except Exception as audit_exc:
            print(f"⚠️ 驳回已生效，但审计日志写入失败：{type(audit_exc).__name__}")
        clear_authorization()
        CURRENT_TOOL_PLAN = []
        STATE = "IDLE"
        print("🛑 圣旨未获批准，操作终止。")
        reset_current_task()
        return None

    if answer.startswith("准奏"):
        parts = answer.split()

        if len(parts) != 2:
            print(
                "🛑 授权格式错误。"
                "例如：准奏 read"
            )
            # 保留待批准计划，允许皇帝重新输入，不销毁已有成果。
            print("ℹ️ 待批准计划已保留，可重新输入「准奏 read」。")
            return None

        permission = parts[1]

        if permission not in PERMISSIONS:
            print(
                f"🛑 未知权限：{permission}"
            )
            print("ℹ️ 待批准计划已保留，可重新输入「准奏 read」。")
            return None

        if not isinstance(CURRENT_TOOL_PLAN, list) or not CURRENT_TOOL_PLAN:
            print("🛑 当前没有有效待审批计划，拒绝授权。")
            clear_authorization()
            CURRENT_TOOL_PLAN = []
            STATE = "IDLE"
            reset_current_task()
            return None

        try:
            bind_plan_approval(
                CURRENT_TOOL_PLAN, permission, "human"
            )
        except (TypeError, ValueError, PermissionError) as exc:
            print(f"🛑 无法绑定审批记录，拒绝授权：{exc}")
            clear_authorization()
            CURRENT_TOOL_PLAN = []
            STATE = "IDLE"
            reset_current_task()
            return None

        try:
            audit_event(
                "approval_bound",
                permission=permission,
                source="human",
                status="approved",
            )
        except Exception as audit_exc:
            clear_authorization()
            CURRENT_TOOL_PLAN = []
            STATE = "IDLE"
            CURRENT_TASK["authorization"] = "none"
            CURRENT_TASK["stage"] = "idle"
            print(
                "🛑 审计日志写入失败，本次授权已取消："
                f"{type(audit_exc).__name__}"
            )
            reset_current_task()
            return None

        authorize(permission)
        STATE = "AUTHORIZED"

        # 记录任务级授权：本次任务已经获得皇帝批准。
        CURRENT_TASK["authorization"] = permission
        CURRENT_TASK["stage"] = "executing"

        return permission

    print("🛑 圣裁无效，本次不执行。")
    clear_authorization()
    CURRENT_TOOL_PLAN = []
    STATE = "IDLE"
    reset_current_task()
    return None


# ============================================================
# 测试：执行第一枚只读兵符
# ============================================================

def execute_read_test(plan):
    global STATE, CURRENT_TOOL_PLAN

    if STATE != "AUTHORIZED":
        raise PermissionError(
            "当前不是 AUTHORIZED 状态，禁止执行。"
        )

    print()
    print("=" * 60)
    print("🔎 中央只读兵符开始执行")
    print("=" * 60)

    try:
        require_permission("read")

        # 刻意保留的独立第二道只读检查：不复用 ALLOWED_READ_TOOLS，
        # 以免上游集合被误改时同时失去两道门。
        read_only_tools = {
            "read_project",
            "read_file",
            "search_project",
        }

        for item in plan:
            tool_name = item.get("name")
            if tool_name not in read_only_tools:
                raise PermissionError(
                    f"只读执行器拒绝非只读工具：{tool_name}"
                )

        results = execute_tool_plan(plan)

        for i, item in enumerate(results, 1):
            print()
            print(f"--- 工具结果 {i} ---")
            print(json.dumps(
                item,
                ensure_ascii=False,
                indent=2
            ))

        print()
        print("=" * 60)
        print("✅ 本轮只读工具执行完成")
        print("=" * 60)

        return results

    finally:
        clear_authorization()
        CURRENT_TOOL_PLAN = []
        STATE = "IDLE"
        print("🔒 本次 read 授权已自动收回。")


# ============================================================
# 主程序
# ============================================================

def infer_project_id(command):
    """
    根据皇帝圣旨中的明确项目名称，安全推断项目 ID。
    无法明确判断时返回 None，不擅自猜测。
    """
    projects = load_projects()
    text = command.lower()

    matches = []

    for project_id, project in projects.items():
        name = str(project.get("name", "")).lower()
        description = str(project.get("description", "")).lower()

        if project_id.lower() in text:
            matches.append(project_id)
            continue

        if name and name in command:
            matches.append(project_id)
            continue

        if description and description in command:
            matches.append(project_id)

    matches = list(dict.fromkeys(matches))

    if len(matches) == 1:
        return matches[0]

    return None


def main():
    global CURRENT_TOOL_PLAN, STATE
    print("""
╔══════════════════════════════════╗
║          丞相府 · AI 中枢         ║
║       中央集权 · 严禁越权执行      ║
╚══════════════════════════════════╝
""")

    print("当前模式：🧠 规划 + 🔐 中央审批 + 🔎 只读兵符")
    print("输入“退出”结束。")
    print()

    history_text = ""

    while True:
        command = input(
            "👑 陛下：> "
        ).strip()
        command = _normalize_approval(command)

        # 新任务下达时清空历轮分析；批准命令则保留，以便后续轮次接续上下文。
        if not command.strip().lower().startswith("准奏") and command.strip().lower() != "驳回":
            history_text = ""

        if command.strip().lower() == "退出":
            clear_authorization()
            print("👋 丞相府关闭。")
            break

        if command.strip().lower() in {"准奏", "准奏 read", "准奏 modify", "准奏 git", "准奏 dangerous", "驳回"}:
            if not CURRENT_TOOL_PLAN:
                print("🔐 当前没有待批准的中央调度单，不能直接执行授权。请先下达具体任务。")
                continue

            permission = approval_flow(command)

            if permission == "退出":
                break

            if permission == "read":
                results = execute_read_test(CURRENT_TOOL_PLAN)
                print()
                print("=" * 60)
                print("🧠 丞相正在接收本轮只读结果")
                print("=" * 60)

                result_text = json.dumps(
                    results,
                    ensure_ascii=False,
                    indent=2
                )

                followup_prompt = f"""
皇帝最初下达的任务是：
{command}

你在此之前各轮已经取得的分析结论（避免重复已读过的内容）：
{history_text or "（这是第一轮）"}

上一轮你已经根据皇帝圣旨制定了只读工具计划。
中央权限层已经批准并执行了该计划。

以下是中央工具返回的真实结果：

--- TOOL_RESULTS ---
{result_text}
--- END_TOOL_RESULTS ---

现在请基于这些真实结果继续完成皇帝原来的任务。

要求：
1. 只能根据实际工具结果分析，不得假装读取了没有返回的文件。
2. 如果还需要读取具体文件，必须重新生成新的 TOOL_PLAN_JSON。
3. 新工具计划只能使用 read_project、read_file、search_project。
4. 新工具计划必须等待皇帝重新批准，绝不能自行执行。
5. 如果不需要继续调用工具，输出：
TOOL_PLAN_JSON: {{"tools":[]}}
"""
                analysis = call_deepseek(
                    followup_prompt,
                    thinking_enabled=False
                )
                history_text += f"\n--- 新一轮分析 ---\n{analysis}"
                next_plan = parse_tool_plan(analysis, allowed_tools=ALLOWED_READ_TOOLS)
                show_tool_plan(next_plan)

                if next_plan:
                    CURRENT_TOOL_PLAN = next_plan
                    print("📜 下一轮只读计划已生成，请再次输入「准奏 read」批准执行。")
                else:
                    print("ℹ️ 本轮分析完成，无需继续调用工具。")
                    CURRENT_TOOL_PLAN = []
                    CURRENT_TASK.update({
                        "goal": None,
                        "success_criteria": [],
                        "project_id": None,
                        "complexity": "unknown",
                        "risk": "unknown",
                        "authorization": "none",
                        "stage": "idle",
                        "completed_steps": [],
                    })
                    clear_authorization()
                    STATE = "IDLE"
                continue

            elif permission == "modify":
                try:
                    results = execute_tool_plan(CURRENT_TOOL_PLAN)
                except Exception as exc:
                    if isinstance(exc, ToolPlanExecutionError):
                        print_tool_plan_report(exc.report)
                    clear_authorization()
                    CURRENT_TOOL_PLAN = []
                    STATE = "IDLE"
                    CURRENT_TASK.update({
                        "goal": None,
                        "success_criteria": [],
                        "project_id": None,
                        "complexity": "unknown",
                        "risk": "unknown",
                        "authorization": "none",
                        "stage": "idle",
                        "completed_steps": [],
                    })
                    print(f"⚠️ 中央修改兵符执行失败，已清理本次授权：{exc}")
                    continue

                print()
                print("=" * 60)
                print("🔧 中央修改兵符执行完成")
                print("=" * 60)
                print(json.dumps(results, ensure_ascii=False, indent=2))
                clear_authorization()
                CURRENT_TOOL_PLAN = []
                STATE = "IDLE"
                CURRENT_TASK.update({
                    "goal": None,
                    "success_criteria": [],
                    "project_id": None,
                    "complexity": "unknown",
                    "risk": "unknown",
                    "authorization": "none",
                    "stage": "idle",
                    "completed_steps": [],
                })
                continue

            else:
                print("⚠️ 当前版本尚未接入该权限执行器。")
                continue

        if not command:
            continue

        if CURRENT_TASK["goal"] is None:
            CURRENT_TASK["goal"] = command
            CURRENT_TASK["success_criteria"] = []
            CURRENT_TASK["project_id"] = None
            CURRENT_TASK["complexity"] = "unknown"
            CURRENT_TASK["risk"] = "unknown"
            CURRENT_TASK["authorization"] = "none"
            CURRENT_TASK["stage"] = "planning"
            CURRENT_TASK["completed_steps"] = []

            inferred_project = infer_project_id(command)

            if inferred_project:
                CURRENT_TASK["project_id"] = inferred_project

        if command in {
            "退出",
            "exit",
            "quit"
        }:
            print("丞相退朝。")
            break

        try:
            content = call_deepseek(command)

            CURRENT_TASK["risk"] = "unknown"
            assessment = parse_task_assessment(content)

            if assessment:
                CURRENT_TASK["goal"] = assessment["goal"]
                CURRENT_TASK["success_criteria"] = assessment["success_criteria"]
                CURRENT_TASK["complexity"] = assessment["complexity"]
                CURRENT_TASK["risk"] = assessment["risk"]
                CURRENT_TASK["stage"] = "planning"

            plan = parse_tool_plan(content)
            show_tool_plan(plan)

            if not plan:
                print("ℹ️ 本轮没有需要执行的工具。")
                CURRENT_TOOL_PLAN = []
                CURRENT_TASK.update({
                    "goal": None,
                    "success_criteria": [],
                    "project_id": None,
                    "complexity": "unknown",
                    "risk": "unknown",
                    "authorization": "none",
                    "stage": "idle",
                    "completed_steps": [],
                })
                clear_authorization()
                STATE = "IDLE"
                continue

            # 低风险任务仅允许绑定并执行纯只读计划。
            # 所有工具计划均须经过人工审批；风险判断不能授予权限。
            permission = approval_flow(command)

            if permission == "退出":
                break

            if permission == "read":
                # 授权状态已由 approval_flow() 在审批成功时置为 AUTHORIZED，
                # 此处不再重复写入。
                results = execute_read_test(plan)

                print()
                print("=" * 60)
                print("🧠 丞相正在接收本轮只读结果")
                print("=" * 60)

                result_text = json.dumps(
                    results,
                    ensure_ascii=False,
                    indent=2
                )

                followup_prompt = f"""
皇帝最初下达的任务是：
{command}

你在此之前各轮已经取得的分析结论（避免重复已读过的内容）：
{history_text or "（这是第一轮）"}

上一轮你已经根据皇帝圣旨制定了只读工具计划。
中央权限层已经批准并执行了该计划。

以下是中央工具返回的真实结果：

【奏报格式】必须简短，最多约12行，只保留重点：
【结论】一句话
【发现】最多3条
【证据】文件名:行号
【风险】低/中/高
【下一步】没有后续读取就写“无需继续读取”
不要重复项目介绍、权限说明、工具返回全文、Token估算或长篇推理。

--- TOOL_RESULTS ---
{result_text}
--- END_TOOL_RESULTS ---

现在请基于这些真实结果继续完成皇帝原来的任务。

要求：
1. 只能根据实际工具结果分析，不得假装读取了没有返回的文件。
2. 指出发现的具体可疑点，并引用文件名、行号和代码片段中的关键信息。
3. 如果现有结果已经足够，请直接给出结论。
4. 如果还需要读取具体文件，必须重新生成新的 TOOL_PLAN_JSON。
5. 新的 TOOL_PLAN_JSON 只能使用 read_project、read_file、search_project。
6. 新工具计划仍然必须等待皇帝重新批准，绝不能自行执行。
7. 如果不需要继续调用工具，输出：
TOOL_PLAN_JSON: {{"tools":[]}}
"""

                analysis = call_deepseek(followup_prompt, thinking_enabled=False)
                history_text += f"\n--- 新一轮分析 ---\n{analysis}"

                next_plan = parse_tool_plan(analysis, allowed_tools=ALLOWED_READ_TOOLS)
                show_tool_plan(next_plan)

                if next_plan:
                    CURRENT_TOOL_PLAN = next_plan
                    print("📜 下一轮只读计划已生成，请再次输入「准奏 read」批准执行。")
                else:
                    print("ℹ️ 本轮分析完成，无需继续调用工具。")
                    CURRENT_TOOL_PLAN = []
                    CURRENT_TASK.update({
                        "goal": None,
                        "success_criteria": [],
                        "project_id": None,
                        "complexity": "unknown",
                        "risk": "unknown",
                        "authorization": "none",
                        "stage": "idle",
                        "completed_steps": [],
                    })
                    clear_authorization()
                    STATE = "IDLE"

            elif permission == "modify":
                results = execute_tool_plan(plan)

                print()
                print("=" * 60)
                print("🔧 中央修改兵符执行完成")
                print("=" * 60)

                for i, item in enumerate(results, 1):
                    print()
                    print(f"--- 工具结果 {i} ---")
                    print(json.dumps(
                        item,
                        ensure_ascii=False,
                        indent=2
                    ))

                clear_authorization()
                CURRENT_TOOL_PLAN = []
                STATE = "IDLE"
                CURRENT_TASK.update({
                    "goal": None,
                    "success_criteria": [],
                    "project_id": None,
                    "complexity": "unknown",
                    "risk": "unknown",
                    "authorization": "none",
                    "stage": "idle",
                    "completed_steps": [],
                })

            elif permission:
                print(
                    f"⚠️ 当前版本尚未接入 "
                    f"{permission} 执行器。"
                )
                clear_authorization()
                CURRENT_TOOL_PLAN = []
                STATE = "IDLE"
                reset_current_task()

        except Exception as e:
            if isinstance(e, ToolPlanExecutionError):
                print_tool_plan_report(e.report)
            clear_authorization()
            CURRENT_TOOL_PLAN = []
            STATE = "IDLE"
            CURRENT_TASK.update({
                "goal": None,
                "success_criteria": [],
                "project_id": None,
                "complexity": "unknown",
                "risk": "unknown",
                "authorization": "none",
                "stage": "idle",
                "completed_steps": [],
            })
            print(
                f"\n🛑 丞相调用失败：{e}"
            )


if __name__ == "__main__":
    main()
