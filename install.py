"""IDA-MCP interactive installer.

Auto-detects system language, copies plugin into IDA's plugins directory,
installs Python dependencies, and writes config.conf.

Usage:
    python install.py
"""

from __future__ import annotations

import json
import locale
import os
import re
import shutil
import subprocess
import sys

# ---------------------------------------------------------------------------
# i18n
# ---------------------------------------------------------------------------

_ZH = "zh"
_EN = "en"

_T: dict = {}


def _detect_lang() -> str:
    try:
        for getter in [locale.getlocale, locale.getdefaultlocale]:
            loc = getter()[0]
            if loc and ("zh" in loc.lower() or "chinese" in loc.lower()):
                return _ZH
    except Exception:
        pass
    if sys.platform == "win32":
        try:
            import ctypes
            windll = ctypes.windll.kernel32
            if windll.GetUserDefaultUILanguage() in range(0x0804, 0x0480 + 1):
                return _ZH
        except Exception:
            pass
    return _EN


def _init_i18n(lang: str) -> None:
    global _T
    _T = {
        # ---- banners ----
        "title": {
            _ZH: "IDA-MCP 交互式安装程序",
            _EN: "IDA-MCP Interactive Installer",
        },
        "done_title": {
            _ZH: "安装完成",
            _EN: "Installation Complete",
        },
        "abort_title": {
            _ZH: "安装已取消",
            _EN: "Installation Aborted",
        },
        # ---- steps ----
        "step_ida": {
            _ZH: "定位 IDA 安装目录",
            _EN: "Locate IDA installation",
        },
        "step_python": {
            _ZH: "定位 IDAPython 解释器",
            _EN: "Locate IDAPython interpreter",
        },
        "step_deps": {
            _ZH: "安装 Python 依赖",
            _EN: "Install Python dependencies",
        },
        "step_copy": {
            _ZH: "安装插件文件",
            _EN: "Install plugin files",
        },
        "step_config": {
            _ZH: "确认配置",
            _EN: "Confirm configuration",
        },
        # ---- prompts ----
        "ida_dir_hint": {
            _ZH: "请输入 IDA 安装根目录（包含 ida.exe / ida 的目录）",
            _EN: "Enter IDA root directory (containing ida.exe / ida)",
        },
        "ida_dir_prompt": {
            _ZH: "IDA 安装目录",
            _EN: "IDA directory",
        },
        "detected": {
            _ZH: "已检测到",
            _EN: "Detected",
        },
        "use_this": {
            _ZH: "使用此路径？",
            _EN: "Use this path?",
        },
        "enter_path": {
            _ZH: "请输入路径",
            _EN: "Enter path",
        },
        "python_hint": {
            _ZH: "IDAPython 解释器（由 idaswitch 管理），需要安装 fastmcp / pytest / colorama",
            _EN: "IDAPython interpreter (managed by idaswitch); must have fastmcp/pytest/colorama",
        },
        "python_not_detected": {
            _ZH: "未能自动检测，请手动输入 IDAPython 可执行文件路径",
            _EN: "Could not auto-detect; please enter the IDAPython executable path",
        },
        "install_deps": {
            _ZH: "是否安装依赖到该 Python 环境？",
            _EN: "Install dependencies into this Python?",
        },
        "installing_deps": {
            _ZH: "正在安装依赖",
            _EN: "Installing dependencies",
        },
        "deps_failed": {
            _ZH: "依赖安装失败",
            _EN: "Dependency installation failed",
        },
        "continue_anyway": {
            _ZH: "仍然继续？",
            _EN: "Continue anyway?",
        },
        "skipped": {
            _ZH: "已跳过。请确保依赖已手动安装。",
            _EN: "Skipped. Make sure dependencies are installed manually.",
        },
        "plugins_not_found": {
            _ZH: "plugins/ 目录不存在，将自动创建",
            _EN: "plugins/ directory not found, will create",
        },
        "not_found": {
            _ZH: "未找到",
            _EN: "Not found",
        },
        "path_empty": {
            _ZH: "路径不能为空",
            _EN: "Path cannot be empty",
        },
        "use_anyway": {
            _ZH: "仍然使用此路径？",
            _EN: "Use this path anyway?",
        },
        "yes_no_hint": {
            _ZH: "请输入 y 或 n",
            _EN: "Please enter y or n",
        },
        "source_missing": {
            _ZH: "源文件未找到",
            _EN: "Source not found",
        },
        "copied": {
            _ZH: "已复制",
            _EN: "Copied",
        },
        "config_written": {
            _ZH: "配置已写入",
            _EN: "Config written to",
        },
        "confirm_config": {
            _ZH: "请确认以下配置（直接回车确认，输入 n 修改）",
            _EN: "Confirm configuration (Enter to accept, n to edit)",
        },
        "config_ida_path": {
            _ZH: "IDA 可执行文件路径",
            _EN: "IDA executable",
        },
        "config_ida_python": {
            _ZH: "IDAPython 解释器",
            _EN: "IDAPython interpreter",
        },
        "config_http_host": {
            _ZH: "HTTP 网关监听地址",
            _EN: "HTTP gateway bind address",
        },
        "config_http_port": {
            _ZH: "HTTP 网关端口",
            _EN: "HTTP gateway port",
        },
        "config_enable_unsafe": {
            _ZH: "启用 unsafe 工具（py_eval、调试器）",
            _EN: "Enable unsafe tools (py_eval, debugger)",
        },
        "config_auto_start": {
            _ZH: "IDA 打开数据库时自动启动插件",
            _EN: "Auto-start plugin when IDA opens a database",
        },
        "config_open_in_ida_autonomous": {
            _ZH: "open_in_ida 默认追加 -A 参数",
            _EN: "open_in_ida defaults to appending -A",
        },
        "config_request_timeout": {
            _ZH: "请求超时（秒）",
            _EN: "Request timeout (seconds)",
        },
        "config_debug": {
            _ZH: "启用调试日志",
            _EN: "Enable debug logging",
        },
        "edit_which": {
            _ZH: "输入要修改的配置编号（逗号分隔），直接回车确认全部",
            _EN: "Enter config numbers to edit (comma-separated), Enter to confirm all",
        },
        "new_value": {
            _ZH: "新值",
            _EN: "New value",
        },
        "invalid_number": {
            _ZH: "无效编号",
            _EN: "Invalid number",
        },
        # ---- summary ----
        "summary_installed_to": {
            _ZH: "插件安装到",
            _EN: "Plugin installed to",
        },
        "summary_auto_start": {
            _ZH: "自动启动",
            _EN: "Auto-start",
        },
        "enabled": {
            _ZH: "已启用",
            _EN: "enabled",
        },
        "disabled": {
            _ZH: "已禁用",
            _EN: "disabled",
        },
        "open_db_hint": {
            _ZH: "在 IDA 中打开数据库即可激活插件。",
            _EN: "Open a database in IDA to activate the plugin.",
        },
    }.copy()


def t(key: str) -> str:
    return _T[key].get(_lang, _T[key][_EN])


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------

_BOLD = "\033[1m"
_DIM = "\033[2m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_CYAN = "\033[36m"
_RESET = "\033[0m"


def _supports_color() -> bool:
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
            return True
        except Exception:
            return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


_COLOR = False


def _s(text: str, *codes: str) -> str:
    if not _COLOR:
        return text
    return "".join(codes) + text + _RESET


def _banner(title: str) -> None:
    w = 58
    print()
    print(_s("  " + "=" * w, _BOLD))
    print(_s(f"   {title}", _BOLD, _CYAN))
    print(_s("  " + "=" * w, _BOLD))


def _step(num: int, total: int, title: str) -> None:
    print()
    print(_s(f"  ── [{num}/{total}] {title} ──", _BOLD, _CYAN))


def _info(msg: str) -> None:
    print(f"  {_s('●', _GREEN)} {msg}")


def _warn(msg: str) -> None:
    print(f"  {_s('▲', _YELLOW)} {msg}")


def _error(msg: str) -> None:
    print(f"  {_s('✖', _RED)} {msg}")


def _yes(prompt: str, default: bool = True) -> bool:
    y, n = ("Y", "n") if default else ("y", "N")
    suffix = _s(f"[{y}/{n}]", _DIM)
    while True:
        ans = input(f"  {prompt} {suffix} ").strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes", t("enabled").lower()):
            return True
        if ans in ("n", "no", t("disabled").lower()):
            return False
        _warn(t("yes_no_hint"))


def _ask_path(prompt: str, must_exist: bool = True) -> str:
    while True:
        path = input(f"  {_s('▸', _CYAN)} {prompt}: ").strip().strip('"').strip("'")
        if not path:
            _warn(t("path_empty"))
            continue
        path = os.path.expanduser(path)
        if must_exist and not os.path.exists(path):
            _warn(f"{t('not_found')}: {path}")
            if _yes(t("use_anyway"), default=False):
                return path
            continue
        return path


def _ask_value(label: str, current: str) -> str:
    ans = input(f"    {label} {_s(f'[{current}]', _DIM)}: ").strip().strip('"').strip("'")
    return ans if ans else current


# ---------------------------------------------------------------------------
# Detection helpers
# ---------------------------------------------------------------------------

_PLUGIN_FILES = ["ida_mcp.py", "ida-plugin.json"]
_PLUGIN_DIRS = ["ida_mcp"]


def _find_plugins_dir(ida_dir: str) -> str | None:
    p = os.path.join(ida_dir, "plugins")
    return p if os.path.isdir(p) else None


def _detect_ida_python(ida_dir: str) -> list[dict[str, str]]:
    """Run idapyswitch to discover Python installations managed for IDA.

    Returns a list of dicts ``{"dir": ..., "version": ..., "preferred": bool}``
    sorted with the preferred entry first.
    """
    sw_name = "idapyswitch.exe" if sys.platform == "win32" else "idapyswitch"
    sw_path = os.path.join(ida_dir, sw_name)
    if not os.path.isfile(sw_path):
        return []

    try:
        proc = subprocess.run(
            [sw_path],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=ida_dir,
            input="\n",
        )
        output = proc.stdout + proc.stderr
    except Exception:
        return []

    results: list[dict[str, str]] = []

    # Parse:  #N: version ('tag') (C:\path\to\python3.dll)
    for m in re.finditer(
        r"#(\d+):\s+([\d.]+)\s+\([^)]+\)\s+\((.+?)(?:python3\d*\.dll)?\)",
        output,
    ):
        idx, version, raw_dir = m.group(1), m.group(2), m.group(3).rstrip("\\")
        exe_name = "python.exe" if sys.platform == "win32" else "bin/python3"
        exe_path = os.path.join(raw_dir, exe_name)
        if os.path.isfile(exe_path):
            results.append({
                "index": idx,
                "version": version,
                "dir": raw_dir,
                "exe": exe_path,
            })

    # "previously used" -> mark as preferred and move to front
    pref = re.search(
        r"IDA previously used:\s+.+?\((.+?)(?:python3\d*\.dll)?\)",
        output,
    )
    if pref and results:
        pref_dir = pref.group(1).rstrip("\\")
        for i, r in enumerate(results):
            if r["dir"].lower() == pref_dir.lower():
                results.insert(0, results.pop(i))
                break

    return results

    return None


def _guess_ida_dir() -> str | None:
    if sys.platform == "win32":
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        pf86 = os.environ.get("ProgramFiles(x86)", "")
        for c in [
            r"D:\IDAPro9.3",
            r"D:\IDAPro",
            os.path.join(pf, "IDA Pro"),
            os.path.join(pf, "IDA Freeware"),
        ] + ([os.path.join(pf86, "IDA Pro")] if pf86 else []):
            if os.path.isdir(c):
                return c
    elif sys.platform == "darwin":
        for c in ["/Applications/IDA Pro", "/Applications/IDA Freeware"]:
            if os.path.isdir(c):
                return c
    else:
        for c in ["/opt/ida", "/opt/ida-pro", os.path.expanduser("~/ida")]:
            if os.path.isdir(c):
                return c
    return None


def _install_deps(python_exe: str, requirements: str) -> bool:
    _info(f"{t('installing_deps')} ...")
    try:
        subprocess.check_call(
            [python_exe, "-m", "pip", "install", "-r", requirements],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        # retry with visible output for diagnosis
        try:
            subprocess.check_call([python_exe, "-m", "pip", "install", "-r", requirements])
            return True
        except subprocess.CalledProcessError:
            return False
    except FileNotFoundError:
        _error(f"Cannot execute: {python_exe}")
        return False


def _write_config(config_path: str, values: dict[str, str]) -> None:
    lines: list[str] = []
    if os.path.isfile(config_path):
        with open(config_path, encoding="utf-8") as f:
            lines = f.readlines()

    updated: set[str] = set()
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)([\w_]+)(\s*=\s*)", line)
        if m and m.group(2) in values:
            key = m.group(2)
            lines[i] = f'{m.group(1)}{key}{m.group(3)}{values[key]}\n'
            updated.add(key)

    for key, val in values.items():
        if key not in updated:
            lines.append(f'{key} = {val}\n')

    with open(config_path, "w", encoding="utf-8") as f:
        f.writelines(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

_lang = _EN
_TOTAL_STEPS = 5


def main() -> None:
    global _COLOR, _lang

    _COLOR = _supports_color()
    _lang = _detect_lang()
    _init_i18n(_lang)

    repo_root = os.path.dirname(os.path.abspath(__file__))
    requirements = os.path.join(repo_root, "requirements.txt")

    _banner(t("title"))

    # ==================================================================
    # Step 1: IDA installation directory
    # ==================================================================
    _step(1, _TOTAL_STEPS, t("step_ida"))
    _info(t("ida_dir_hint"))

    guessed_ida = _guess_ida_dir()
    if guessed_ida:
        _info(f"{t('detected')}: {guessed_ida}")
        if _yes(t("use_this")):
            ida_dir = guessed_ida
        else:
            ida_dir = _ask_path(t("ida_dir_prompt"))
    else:
        ida_dir = _ask_path(t("ida_dir_prompt"))

    plugins_dir = _find_plugins_dir(ida_dir)
    if not plugins_dir:
        plugins_dir = os.path.join(ida_dir, "plugins")
        _warn(f"{t('plugins_not_found')}: {plugins_dir}")

    _info(f"plugins/ → {plugins_dir}")

    # ==================================================================
    # Step 2: IDAPython executable
    # ==================================================================
    _step(2, _TOTAL_STEPS, t("step_python"))
    _info(t("python_hint"))

    python_installations = _detect_ida_python(ida_dir)
    ida_python: str | None = None

    if python_installations:
        print()
        for inst in python_installations:
            tag = f" ({_s('preferred', _GREEN)})" if inst is python_installations[0] else ""
            print(f"    {_s('#' + inst['index'], _DIM)}  Python {inst['version']}  →  {inst['exe']}{tag}")
        print()

        _info(f"{t('detected')}: Python {python_installations[0]['version']}")
        if _yes(t("use_this")):
            ida_python = python_installations[0]["exe"]
        else:
            ans = input(f"  {_s('▸', _CYAN)} #{t('enter_path')} / #N: ").strip()
            # User may type a number to pick from the list
            if ans.startswith("#") and ans[1:].isdigit():
                idx = int(ans[1:])
                for inst in python_installations:
                    if inst["index"] == str(idx):
                        ida_python = inst["exe"]
                        break
            if ida_python is None and ans.isdigit():
                n = int(ans)
                if 0 <= n < len(python_installations):
                    ida_python = python_installations[n]["exe"]

    if ida_python is None:
        _warn(t("python_not_detected"))
        ida_python = _ask_path(t("enter_path"))

    _info(f"IDAPython → {ida_python}")

    # ==================================================================
    # Step 3: Install dependencies
    # ==================================================================
    _step(3, _TOTAL_STEPS, t("step_deps"))
    if _yes(t("install_deps")):
        if _install_deps(ida_python, requirements):
            _info("fastmcp, pytest, colorama  OK")
        else:
            _error(t("deps_failed"))
            if not _yes(t("continue_anyway"), default=False):
                _banner(t("abort_title"))
                sys.exit(1)
    else:
        _warn(t("skipped"))

    # ==================================================================
    # Step 4: Copy plugin files
    # ==================================================================
    _step(4, _TOTAL_STEPS, t("step_copy"))
    os.makedirs(plugins_dir, exist_ok=True)

    for name in _PLUGIN_FILES:
        src = os.path.join(repo_root, name)
        dst = os.path.join(plugins_dir, name)
        if os.path.isfile(src):
            shutil.copy2(src, dst)
            _info(f"{t('copied')}: {name}")
        else:
            _warn(f"{t('source_missing')}: {name}")

    for name in _PLUGIN_DIRS:
        src = os.path.join(repo_root, name)
        dst = os.path.join(plugins_dir, name)
        if os.path.isdir(src):
            if os.path.isdir(dst):
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
            _info(f"{t('copied')}: {name}/")
        else:
            _warn(f"{t('source_missing')}: {name}/")

    # ==================================================================
    # Step 5: Confirm configuration
    # ==================================================================
    _step(5, _TOTAL_STEPS, t("step_config"))

    ida_exe_name = "ida.exe" if sys.platform == "win32" else "ida"
    ida_exe = os.path.join(ida_dir, ida_exe_name)

    # Build config items for interactive review
    config_items = [
        ("ida_path",                t("config_ida_path"),               f'"{ida_exe}"',          "str"),
        ("ida_python",              t("config_ida_python"),             f'"{ida_python}"',       "str"),
        ("enable_unsafe",           t("config_enable_unsafe"),          "true",                  "bool"),
        ("auto_start",              t("config_auto_start"),             "true",                  "bool"),
        ("open_in_ida_autonomous",  t("config_open_in_ida_autonomous"), "true",                  "bool"),
        ("http_host",               t("config_http_host"),              '"127.0.0.1"',           "str"),
        ("http_port",               t("config_http_port"),              "11338",                 "int"),
        ("request_timeout",         t("config_request_timeout"),        "30",                    "int"),
        ("debug",                   t("config_debug"),                  "false",                 "bool"),
    ]

    while True:
        print()
        for i, (key, label, default_val, _type) in enumerate(config_items, 1):
            val = default_val.strip('"')
            print(f"    {_s(f'{i}.', _DIM)} {label}")
            print(f"       {key} = {_s(val, _BOLD)}")

        print()
        ans = input(f"  {t('edit_which')} ").strip()

        if not ans:
            break

        try:
            indices = [int(x.strip()) for x in ans.split(",") if x.strip()]
            for idx in indices:
                if 1 <= idx <= len(config_items):
                    key, label, cur_val, ctype = config_items[idx - 1]
                    new_val = _ask_value(f"{key} =", cur_val.strip('"'))
                    if ctype == "bool":
                        new_val = "true" if new_val.lower() in ("true", "yes", "y", "1") else "false"
                        config_items[idx - 1] = (key, label, new_val, ctype)
                    elif ctype == "int":
                        int(new_val)  # validate
                        config_items[idx - 1] = (key, label, new_val, ctype)
                    else:
                        config_items[idx - 1] = (key, label, f'"{new_val}"', ctype)
                else:
                    _warn(f"{t('invalid_number')}: {idx}")
        except ValueError:
            _warn(t("invalid_number"))

    config_values = {item[0]: item[2] for item in config_items}
    config_path = os.path.join(plugins_dir, "ida_mcp", "config.conf")
    _write_config(config_path, config_values)
    _info(f"{t('config_written')}: {config_path}")

    # ==================================================================
    # Done
    # ==================================================================
    auto_start_val = config_values.get("auto_start", "false")
    _banner(t("done_title"))
    _info(f"{t('summary_installed_to')}: {plugins_dir}")
    _info(f"IDAPython:        {ida_python}")
    _info(f"IDA:              {ida_exe}")
    _info(f"{t('config_auto_start')}: {t('enabled') if auto_start_val == 'true' else t('disabled')}")
    print()
    _info(t("open_db_hint"))
    print()


if __name__ == "__main__":
    main()
