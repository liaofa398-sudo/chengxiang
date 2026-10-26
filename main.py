import json
import os
import stat
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
    # 避免审计路径被替换为 FIFO 时，打开操作无限等待。
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK

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
    finally:
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
    return order.get(permission, 999)


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

def safe_project_path(project):
    """
    根据户籍解析项目路径。

    当前只允许明确登记过的本地 path。
    repository / Codespace 暂时不执行实际访问。
    """
    path = project.get("path")

    if not path:
        return None

    expanded = Path(path).expanduser().resolve()

    # 安全边界：
    # 当前只允许访问用户 Home 目录下的路径。
    home = Path.home().resolve()

    try:
        relative_home_path = expanded.relative_to(home)
    except ValueError:
        raise PermissionError(
            "项目路径超出当前用户 Home 目录，拒绝读取。"
        )

    forbidden_dirs = globals().get("FORBIDDEN_READ_DIRS", set())
    if any(part.lower() in forbidden_dirs for part in relative_home_path.parts):
        raise PermissionError(
            "项目路径位于敏感目录内，拒绝访问。"
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

# 即使文件名看似普通，也不进入常见的凭据/私钥目录。
FORBIDDEN_READ_DIRS = {
    ".ssh",
    ".gnupg",
    ".aws",
    ".azure",
    ".kube",
    ".docker",
    ".npm",
}

IGNORED_SEARCH_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
}

# 修改兵符只接受不超过 1 MiB 的文本文件，避免误读超大文件。
MAX_MODIFY_BYTES = 1024 * 1024

# 限制只读扫描的总工作量，避免超大文件或海量目录拖垮进程。
MAX_LINE_READ_FILE_BYTES = 10 * 1024 * 1024
MAX_SEARCH_PATHS = 20000
MAX_SEARCH_FILES = 5000
MAX_SEARCH_BYTES = 10 * 1024 * 1024


def read_modify_target_bounded(path):
    """有硬字节上限地读取 UTF-8 文本，避免整文件无界载入内存。"""
    with path.open("rb") as source:
        raw = source.read(MAX_MODIFY_BYTES + 1)

    if len(raw) > MAX_MODIFY_BYTES:
        raise ValueError(
            f"修改已拒绝：目标文件超过 {MAX_MODIFY_BYTES} bytes 上限。"
        )

    return raw.decode("utf-8")


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


def require_task_project_scope(project_id):
    """
    将工具调用绑定到皇帝当前明确指定的单一项目。
    未明确项目或试图跨项目时一律拒绝；提示词不是安全边界。
    """
    if not isinstance(project_id, str) or not project_id:
        raise PermissionError("拒绝执行：项目 ID 无效。")

    task_project_id = CURRENT_TASK.get("project_id")
    if not task_project_id:
        raise PermissionError(
            "拒绝执行：当前任务尚未绑定明确项目。"
            "请在任务描述中写出已登记的项目 ID 或项目名称。"
        )

    if project_id != task_project_id:
        raise PermissionError(
            f"拒绝跨项目操作：当前任务绑定 {task_project_id}，"
            f"工具请求的是 {project_id}。"
        )

    try:
        get_registered_project(project_id)
    except ValueError as exc:
        raise PermissionError(f"项目未登记：{project_id}") from exc


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


def read_file(project_id, relative_path, start_line=None, end_line=None, max_bytes=30000):
    """
    精确读取项目内的单个文本文件。
    支持可选行范围：
    start_line / end_line 均为 1-based，包含首尾。
    """
    require_permission("read")
    require_task_project_scope(project_id)

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
            or name in FORBIDDEN_READ_DIRS
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

    if start_line is not None or end_line is not None:
        if start_line is None:
            start_line = 1
        if end_line is None:
            end_line = start_line + 200

        if not isinstance(start_line, int) or not isinstance(end_line, int):
            raise ValueError("start_line 和 end_line 必须是整数。")

        if start_line < 1 or end_line < start_line:
            raise ValueError("行范围无效。")

        if end_line - start_line + 1 > 500:
            raise ValueError("单次最多读取 500 行。")

    size = target.stat().st_size
    has_line_range = start_line is not None or end_line is not None

    # 行范围读取仍需逐行扫描文件；对超大文件直接拒绝，避免单行或总扫描量无界。
    if has_line_range and size > MAX_LINE_READ_FILE_BYTES:
        raise ValueError(
            f"文件超过行范围读取上限 {MAX_LINE_READ_FILE_BYTES} bytes，拒绝扫描。"
        )

    # 无行范围时，先检查大小，再读取，避免先把超大文件整体载入内存。
    if not has_line_range and size > max_bytes:
        raise ValueError(
            f"文件过大：{relative_path} ({size} bytes)，"
            f"单次最多读取 {max_bytes} bytes。"
        )

    try:
        if has_line_range:
            selected = []
            selected_bytes = 0
            total_lines = 0

            # 逐行读取，只保留请求范围；不把整个文件读入内存。
            with target.open("r", encoding="utf-8", errors="replace") as source:
                for line_number, line in enumerate(source, 1):
                    total_lines = line_number
                    if start_line <= line_number <= end_line:
                        line = line.rstrip("\r\n")
                        line_bytes = len(line.encode("utf-8"))
                        added_bytes = line_bytes + (1 if selected else 0)
                        if selected_bytes + added_bytes > max_bytes:
                            raise ValueError(
                                f"指定行范围过大，单次最多返回 {max_bytes} bytes。"
                            )
                        selected.append(line)
                        selected_bytes += added_bytes

            if start_line > total_lines:
                raise ValueError(
                    f"start_line 超出文件范围：文件共 {total_lines} 行。"
                )

            actual_end_line = min(end_line, total_lines)
            result_content = "\n".join(selected)

            return {
                "project": project_id,
                "status": "ok",
                "file": relative_path,
                "start_line": start_line,
                "end_line": actual_end_line,
                "total_lines": total_lines,
                "bytes": len(result_content.encode("utf-8")),
                "content": result_content
            }

        content = target.read_text(
            encoding="utf-8",
            errors="replace"
        )
    except OSError as e:
        raise RuntimeError(
            f"读取文件失败：{type(e).__name__}"
        ) from e

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
    require_task_project_scope(project_id)

    root = get_local_project_root(project_id)

    if not keyword:
        raise ValueError("搜索关键词不能为空。")

    results = []
    visited_paths = 0
    scanned_files = 0
    scanned_bytes = 0
    scan_truncated = False

    for path in root.rglob("*"):
        visited_paths += 1
        if visited_paths > MAX_SEARCH_PATHS:
            scan_truncated = True
            break
        if len(results) >= max_results:
            scan_truncated = True
            break
        if scanned_files >= MAX_SEARCH_FILES:
            scan_truncated = True
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

        # 跳过整个目录树中的特殊目录和常见凭据目录。
        if any(
            part.lower() in IGNORED_SEARCH_DIRS
            or part.lower() in FORBIDDEN_READ_DIRS
            for part in relative.parts
        ):
            continue

        # 敏感文件硬拒绝
        if is_forbidden_read(path):
            continue

        try:
            size = path.stat().st_size
        except OSError:
            continue

        # 二进制/超大文件不参与普通文本搜索；并限制本轮累计读取量。
        if size > 300 * 1024:
            continue
        if scanned_bytes + size > MAX_SEARCH_BYTES:
            scan_truncated = True
            break

        try:
            text = path.read_text(
                encoding="utf-8",
                errors="replace"
            )
        except (OSError, UnicodeError):
            continue

        scanned_files += 1
        scanned_bytes += size

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
        "count": len(results),
        "scanned_files": scanned_files,
        "scanned_bytes": scanned_bytes,
        "scan_truncated": scan_truncated
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
    require_task_project_scope(project_id)

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
            "message": "登记路径不存在。"
        }

    result = {
        "project": project_id,
        "status": "ok",
        "entries": [],
        "git_status": None
    }

    # 只列出非敏感的一级条目，不暴露绝对路径或敏感文件名。
    try:
        visible_count = 0
        inspected_count = 0
        listing_truncated = False

        # 不先对整个目录排序/物化；目录条目过多时限制扫描量。
        for entry in path.iterdir():
            inspected_count += 1
            if visible_count >= 200 or inspected_count > 2000:
                listing_truncated = True
                break
            if entry.is_symlink():
                continue
            if entry.name.lower() in IGNORED_SEARCH_DIRS:
                continue
            if entry.name.lower() in FORBIDDEN_READ_DIRS:
                continue
            if is_forbidden_read(entry):
                continue

            result["entries"].append({
                "name": entry.name,
                "type": "directory" if entry.is_dir() else "file"
            })
            visible_count += 1

        result["listing_truncated"] = listing_truncated

    except OSError as e:
        result["directory_error"] = type(e).__name__

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
        # 不把远端错误正文原样回显，避免意外暴露请求/服务端敏感信息。
        raise RuntimeError(
            f"DeepSeek API HTTP {e.code}。请检查服务状态与配置，不要粘贴密钥。"
        ) from e

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
    for item in plan:
        if not isinstance(item, dict):
            raise PermissionError("拒绝：计划条目格式无效。")
        name = item.get("name")
        if name in ALLOWED_READ_TOOLS:
            continue
        if name in ALLOWED_MODIFY_TOOLS:
            required = "modify"
            continue
        raise PermissionError(f"拒绝未知工具：{name!r}")
    return required


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


def parse_tool_plan(content):
    global CURRENT_TOOL_PLAN
    CURRENT_TOOL_PLAN = []

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

        if name not in ALLOWED_TOOLS:
            raise PermissionError(f"未知工具：{name}")

        if not isinstance(args, dict):
            raise ValueError("工具参数格式错误。")

        if project_id not in projects:
            raise PermissionError(
                f"项目未登记：{project_id}"
            )

        require_task_project_scope(project_id)

        if name == "modify_file":
            if set(args.keys()) != {"relative_path", "old_text", "new_text"}:
                raise PermissionError(
                    "modify_file 参数必须且只能是：relative_path、old_text、new_text"
                )

        if name == "read_project":
            allowed = set()

        elif name == "read_file":
            allowed = {
                "relative_path",
                "start_line",
                "end_line",
            }

            if "relative_path" not in args:
                raise ValueError("read_file 缺少 relative_path")

            # 中央硬规则：大文件禁止整文件读取，必须使用行范围。
            if "start_line" not in args and "end_line" not in args:
                # 规划阶段只允许在项目根目录内检查文件大小；
                # 不对越界路径、符号链接逃逸或敏感目标执行 stat。
                project = projects.get(project_id)
                if not project:
                    raise PermissionError(
                        f"未知项目：{project_id}"
                    )

                project_root = safe_project_path(project)
                relative_path = args["relative_path"]

                if not isinstance(relative_path, str) or not relative_path.strip():
                    raise ValueError("read_file 的 relative_path 必须是非空字符串。")

                if project_root is not None:
                    target = (project_root / relative_path).resolve()

                    try:
                        resolved_relative = target.relative_to(project_root)
                    except ValueError:
                        raise PermissionError(
                            "规划阶段拒绝检查项目目录之外的文件。"
                        )

                    for component in resolved_relative.parts:
                        name_part = component.lower()
                        if (
                            name_part == ".git"
                            or name_part in FORBIDDEN_READ_NAMES
                            or name_part in FORBIDDEN_READ_DIRS
                            or any(
                                name_part.endswith(suffix)
                                for suffix in FORBIDDEN_READ_SUFFIXES
                            )
                        ):
                            raise PermissionError(
                                "规划阶段拒绝检查敏感路径的文件大小。"
                            )

                    if target.exists() and target.is_file():
                        size = target.stat().st_size

                        if size > 30000:
                            raise PermissionError(
                                f"文件过大：{relative_path} "
                                f"({size} bytes)。"
                                "超过 30000 bytes，"
                                "必须使用 start_line/end_line 分段读取。"
                            )

            if "start_line" in args:
                if not isinstance(args["start_line"], int):
                    raise ValueError("start_line 必须是整数")
                if args["start_line"] < 1:
                    raise ValueError("start_line 必须 >= 1")

            if "end_line" in args:
                if not isinstance(args["end_line"], int):
                    raise ValueError("end_line 必须是整数")
                if args["end_line"] < 1:
                    raise ValueError("end_line 必须 >= 1")

            if (
                "start_line" in args
                and "end_line" in args
                and args["end_line"] < args["start_line"]
            ):
                raise ValueError(
                    "end_line 不能小于 start_line"
                )

        elif name == "modify_file":
            allowed = {
                "relative_path",
                "old_text",
                "new_text",
            }

        elif name == "search_project":
            allowed = {"keyword"}
            if "keyword" not in args:
                raise ValueError("search_project 缺少 keyword")

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
        for i, item in enumerate(plan, 1):
            print(
                f"{i}. {item['name']}("
                f"{item['project_id']}, "
                f"{json.dumps(item['args'], ensure_ascii=False)})"
            )

    print("=" * 60)



def modify_file(project_id, relative_path, old_text, new_text):
    """
    中央 modify 兵符：
    - 必须拥有 modify 权限
    - 只能操作已登记项目
    - 禁止 .env / 密钥 / Git 文件
    - 修改前自动备份
    - 必须精确匹配 old_text，防止误改
    """
    require_permission("modify")
    require_task_project_scope(project_id)

    try:
        get_registered_project(project_id)
    except ValueError as exc:
        raise PermissionError(f"未知项目：{project_id}") from exc

    from pathlib import PurePosixPath, PureWindowsPath

    if not isinstance(relative_path, str) or not relative_path.strip():
        raise PermissionError("拒绝空白或无效的目标路径。")

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

        if name in forbidden_components or name in FORBIDDEN_READ_DIRS:
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
    target = (root / normalized).resolve()

    try:
        target.relative_to(root)
    except ValueError:
        raise PermissionError("目标文件越出项目目录。")

    # 对解析符号链接后的真实路径再次检查敏感组件。
    resolved_relative = target.relative_to(root)
    for component in resolved_relative.parts:
        name = component.lower()
        if name in forbidden_components or name in FORBIDDEN_READ_DIRS or any(
            name.endswith(suffix)
            for suffix in FORBIDDEN_READ_SUFFIXES
        ):
            raise PermissionError(
                f"中央禁止修改敏感目标：{relative_path}"
            )

    if not target.exists() or not target.is_file():
        raise FileNotFoundError(f"目标文件不存在：{relative_path}")

    if not isinstance(old_text, str) or not isinstance(new_text, str):
        raise PermissionError("old_text 和 new_text 必须是字符串。")

    # 限制模型提供的替换文本，避免超大参数造成内存/磁盘消耗。
    if len(old_text) > MAX_MODIFY_BYTES or len(new_text) > MAX_MODIFY_BYTES:
        raise PermissionError(
            f"替换文本长度超过 {MAX_MODIFY_BYTES} 字符上限。"
        )
    if len(old_text.encode("utf-8")) > MAX_MODIFY_BYTES:
        raise PermissionError("old_text 超过 1 MiB 字节上限。")
    if len(new_text.encode("utf-8")) > MAX_MODIFY_BYTES:
        raise PermissionError("new_text 超过 1 MiB 字节上限。")

    if old_text == "":
        raise PermissionError("禁止空 old_text 修改，防止误插入。")

    content = read_modify_target_bounded(target)
    # 记录读取时的内容指纹，用于发现并发修改。
    import hashlib
    original_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

    count = content.count(old_text)

    if count == 0:
        raise ValueError("未找到精确匹配内容，未修改文件。")

    if count > 1:
        raise ValueError(
            f"找到 {count} 处匹配，无法确认唯一修改位置，未修改文件。"
        )

    new_content = content.replace(old_text, new_text, 1)
    if len(new_content.encode("utf-8")) > MAX_MODIFY_BYTES:
        raise PermissionError(
            f"修改后文件超过 {MAX_MODIFY_BYTES} bytes 上限，未写入。"
        )

    backup = target.with_name(
        target.name + ".before_chengxiang_modify.bak"
    )

    # lexists 能识别断开的符号链接，不能只依赖 exists。
    import os

    if os.path.lexists(backup):
        raise FileExistsError(
            f"安全停止：备份路径已存在或被占用，请先人工确认：{backup}"
        )

    # 独占创建备份，拒绝覆盖已存在的路径。
    backup_created = False
    try:
        with backup.open("x", encoding="utf-8") as backup_file:
            backup_created = True
            backup_file.write(content)
            backup_file.flush()
            os.fsync(backup_file.fileno())
    except FileExistsError:
        raise FileExistsError(
            f"安全停止：备份路径已被占用，请先人工确认：{backup}"
        )
    except BaseException as original_error:
        if backup_created:
            try:
                backup.unlink()
            except OSError as cleanup_error:
                raise RuntimeError(
                    "备份写入失败，且清理残留备份失败。"
                    f"请人工检查：{backup}；清理错误：{cleanup_error}"
                ) from original_error
        raise

    # 同目录临时文件：完整写入后再替换正式文件。
    import os
    import tempfile
    import stat

    original_mode = stat.S_IMODE(target.stat().st_mode)
    temp_path = None

    try:
        fd, temp_name = tempfile.mkstemp(
            prefix=".chengxiang_tmp_",
            suffix=".tmp",
            dir=str(target.parent),
        )
        temp_path = Path(temp_name)

        with os.fdopen(fd, "w", encoding="utf-8") as temp_file:
            temp_file.write(new_content)
            temp_file.flush()
            os.fsync(temp_file.fileno())

        os.chmod(temp_path, original_mode)

        # 替换前复核内容；若文件已变化，拒绝覆盖。
        current_content = read_modify_target_bounded(target)
        current_hash = hashlib.sha256(
            current_content.encode("utf-8")
        ).hexdigest()
        if current_hash != original_hash:
            raise RuntimeError(
                "安全停止：目标文件在读取后发生变化，拒绝覆盖。"
                f"原始备份保留：{backup}"
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

        name = item["name"]
        if name in ALLOWED_READ_TOOLS:
            required = "read"
        elif name in ALLOWED_MODIFY_TOOLS:
            required = "modify"
        else:
            raise PermissionError(f"拒绝执行未知工具：{name!r}")

        if not isinstance(item["args"], dict):
            raise PermissionError("拒绝执行：工具参数必须为对象。")
        if permission_level(approved_permission) < permission_level(required):
            raise PermissionError(
                f"拒绝执行：批准权限不足，工具 {name!r} 需要 {required}。"
            )

    source_name = approval.get("source", "human")
    audit_event(
        "execution_started",
        permission=approved_permission,
        source=source_name,
        status="started",
    )

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

            # 审批后、每项真正执行前再次核验项目范围。
            require_task_project_scope(project_id)

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

def approval_flow(answer=None):
    """
    当前版本仍采用人工批准。
    不允许 DeepSeek 自己决定批准。
    """
    global STATE, CURRENT_TOOL_PLAN

    if answer is None:
        print()
        print("🔐 中央审批")
        print("输入：")
        print("  准奏 read")
        print("  准奏 modify")
        print("  驳回")
        print()
        answer = input("👑 圣裁：> ").strip()
    else:
        answer = answer.strip()

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
            clear_authorization()
            CURRENT_TOOL_PLAN = []
            STATE = "IDLE"
            reset_current_task()
            return None

        permission = parts[1]

        if permission not in PERMISSIONS:
            print(
                f"🛑 未知权限：{permission}"
            )
            clear_authorization()
            CURRENT_TOOL_PLAN = []
            STATE = "IDLE"
            reset_current_task()
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

    while True:
        command = input(
            "👑 陛下：> "
        ).strip()

        if command.strip().lower() == "退出":
            clear_authorization()
            print("👋 丞相府关闭。")
            break

        if command.strip().lower() in {"准奏", "准奏 read", "准奏 modify", "准奏 git", "准奏 dangerous", "驳回"}:
            if not CURRENT_TOOL_PLAN:
                print("🔐 当前没有待批准的中央调度单，不能直接执行授权。请先下达具体任务。")
                continue

            permission = approval_flow(answer=command)

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
                next_plan = parse_tool_plan(analysis)
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
            permission = approval_flow()

            if permission == "退出":
                break

            if permission == "read":
                # 中央权限层已授予 read；执行前确保状态机进入执行态。
                STATE = "AUTHORIZED"
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

                next_plan = parse_tool_plan(analysis)
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
