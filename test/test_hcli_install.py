"""Tests for the idalib-only configure script (scripts/hcli_install.py)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "hcli_install.py"
SPEC = importlib.util.spec_from_file_location("hcli_install", MODULE_PATH)
assert SPEC and SPEC.loader


def _load(monkeypatch, tmp_path):
    module = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(module)
    monkeypatch.setattr(module, "default_ida_user_dir", lambda: tmp_path)
    return module


def test_resolve_install_dir_reads_ida_config(monkeypatch, tmp_path):
    module = _load(monkeypatch, tmp_path)
    (tmp_path / "ida-config.json").write_text(
        '{"Paths": {"ida-install-dir": "%s"}}' % tmp_path.as_posix(), encoding="utf-8"
    )
    assert module.resolve_install_dir(None) == tmp_path


def test_resolve_install_dir_prefers_explicit_and_idadir(monkeypatch, tmp_path):
    module = _load(monkeypatch, tmp_path)
    monkeypatch.setenv("IDADIR", str(tmp_path))
    assert module.resolve_install_dir(None) == tmp_path
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    assert module.resolve_install_dir(str(explicit)) == explicit


def test_resolve_install_dir_missing_dir_raises(monkeypatch, tmp_path):
    module = _load(monkeypatch, tmp_path)
    try:
        module.resolve_install_dir(str(tmp_path / "missing"))
    except FileNotFoundError:
        pass
    else:
        raise AssertionError("expected FileNotFoundError")


def test_bundled_python_candidates_include_versioned(monkeypatch, tmp_path):
    module = _load(monkeypatch, tmp_path)
    bin_dir = tmp_path / "ida-python" / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "python3.12").touch()
    names = [p.name for p in module.bundled_python_candidates(tmp_path)]
    assert "python3.12" in names


def test_resolve_idalib_python_probes_in_order(monkeypatch, tmp_path):
    module = _load(monkeypatch, tmp_path)
    probed: list[Path] = []

    good = tmp_path / "good-python"
    good.touch()

    def fake_can(python, _install_dir):
        probed.append(python)
        return python == good

    monkeypatch.setattr(module, "can_idalib", fake_can)
    found = module.resolve_idalib_python(None, str(good))
    assert found == good
    assert probed and probed[-1] == good

    # Nothing importable -> None
    monkeypatch.setattr(module, "can_idalib", lambda *_a: False)
    assert module.resolve_idalib_python(tmp_path, None) is None


def test_main_persists_and_prints(monkeypatch, tmp_path, capsys):
    module = _load(monkeypatch, tmp_path)
    persisted: dict[str, str] = {}

    monkeypatch.setattr(module, "resolve_install_dir", lambda _explicit: tmp_path)
    good = tmp_path / "python3.12"
    good.touch()
    monkeypatch.setattr(module, "resolve_idalib_python", lambda _d, _p: good)
    monkeypatch.setattr(
        module,
        "persist_ida_python",
        lambda python: persisted.update({"ida_python": str(python)}) or True,
    )

    assert module.main([]) == 0
    out = capsys.readouterr().out
    assert str(good) in out
    assert persisted == {"ida_python": str(good)}


def test_main_errors_without_idalib_python(monkeypatch, tmp_path, capsys):
    module = _load(monkeypatch, tmp_path)
    monkeypatch.setattr(module, "resolve_install_dir", lambda _e: tmp_path)
    monkeypatch.setattr(module, "resolve_idalib_python", lambda _d, _p: None)
    assert module.main([]) == 1
    assert "import idapro" in capsys.readouterr().err
