#!/usr/bin/env python3
"""扫 FastAPI 项目里缺鉴权依赖的路由函数。

退出码：发现问题返回 1，干净返回 0，可直接接 CI。
"""
import argparse
import ast
import json
import sys
from pathlib import Path

ROUTE_METHODS = {"get", "post", "put", "delete", "patch", "head", "options", "trace"}

# 扫描时跳过的目录，避免把虚拟环境和缓存里的代码算进来。
SKIP_DIRS = {"__pycache__", ".venv", "venv", ".git", "node_modules", ".tox", "build", "dist"}


def _name(node):
    """把 Name / Attribute / Call 还原成点分名字，取最后一段用于比较。"""
    if isinstance(node, ast.Call):
        node = node.func
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _tail(node):
    return _name(node).split(".")[-1]


def _is_route(node):
    for dec in node.decorator_list:
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
            if dec.func.attr in ROUTE_METHODS:
                return True
    return False


def _depends_target(call):
    """Depends(x) 返回 x 的短名；不是 Depends 或没传参返回 None。"""
    if not isinstance(call, ast.Call):
        return None
    if _tail(call.func) != "Depends":
        return None
    if not call.args:
        return None
    return _tail(call.args[0])


def _func_has_auth(node, auth_names):
    """检查参数默认值里有没有 Depends(某个鉴权函数)。"""
    defaults = list(node.args.defaults)
    for kw in node.args.kw_defaults:
        if kw is not None:
            defaults.append(kw)
    for default in defaults:
        target = _depends_target(default)
        if target and target in auth_names:
            return True
    return False


def _router_has_auth(tree, auth_names):
    """APIRouter(dependencies=[Depends(x)]) 会让整个文件的路由都带上鉴权。

    不识别这种情况会把「已经受保护的 router」全报成漏洞。
    """
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if _tail(node.value.func) != "APIRouter":
            continue
        for kw in node.value.keywords:
            if kw.arg != "dependencies":
                continue
            for elt in getattr(kw.value, "elts", []):
                target = _depends_target(elt)
                if target and target in auth_names:
                    return True
    return False


def scan_file(path, auth_names, skip_names):
    """返回该文件里缺鉴权的路由 [(行号, 函数名), ...]。"""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (SyntaxError, UnicodeDecodeError):
        # 语法错的文件不归这个工具管，跳过而不是崩掉。
        return []

    if path.name in skip_names:
        return []
    if _router_has_auth(tree, auth_names):
        return []

    missing = []
    # 只看模块顶层的函数：嵌套函数不可能是路由，walk 整个树会误报。
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not _is_route(node):
            continue
        if _func_has_auth(node, auth_names):
            continue
        missing.append((node.lineno, node.name))
    return missing


def iter_py_files(root):
    for path in sorted(root.rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        yield path


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="扫 FastAPI 项目里缺鉴权依赖的路由函数",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例:\n"
            "  python auth_audit.py ./app\n"
            "  python auth_audit.py ./app --auth get_current_admin require_user\n"
            "  python auth_audit.py ./app --exclude auth.py login.py\n"
        ),
    )
    parser.add_argument("path", help="要扫描的目录")
    parser.add_argument(
        "--auth",
        nargs="+",
        default=["get_current_user"],
        metavar="NAME",
        help="鉴权依赖的函数名，可传多个（默认 get_current_user）",
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        default=[],
        metavar="FILE",
        help="跳过的文件名，如 auth.py（登录接口本来就不需要鉴权）",
    )
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    root = Path(args.path)
    if not root.is_dir():
        parser.error(f"不是目录: {root}")

    auth_names = set(args.auth)
    skip_names = set(args.exclude)

    findings = []
    for path in iter_py_files(root):
        for lineno, func in scan_file(path, auth_names, skip_names):
            findings.append({
                "file": str(path.relative_to(root)),
                "line": lineno,
                "function": func,
            })

    if args.json:
        print(json.dumps({"count": len(findings), "findings": findings}, ensure_ascii=False, indent=2))
    else:
        for item in findings:
            print(f"{item['file']}:{item['line']}  {item['function']}")
        if findings:
            print(f"\n共 {len(findings)} 处")
        else:
            print("没发现问题。")

    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
