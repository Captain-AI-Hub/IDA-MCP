"""Business logic for managing IDE skills."""

from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from app.services.settings_service import SettingsService


class SkillService:
    def __init__(self, settings_service: SettingsService | None = None) -> None:
        self._settings_service = settings_service or SettingsService()

    def import_skill_zip(self, zip_path: str | Path) -> dict[str, Any]:
        """Import a skill package ZIP and persist its metadata."""
        zip_path = Path(zip_path)
        file_name = zip_path.name

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp = Path(tmp_dir)
            with zipfile.ZipFile(zip_path, "r") as zf:
                for info in zf.infolist():
                    name = info.filename
                    if (
                        ".." in name
                        or name.startswith(("/", "\\"))
                        or PurePosixPath(name).is_absolute()
                        or PureWindowsPath(name).is_absolute()
                    ):
                        raise ValueError(f"Invalid path in ZIP: {name}")
                zf.extractall(tmp)

            manifest = None
            skill_root = tmp
            for candidate in (tmp / "skill.json", tmp / "package.json"):
                if candidate.exists():
                    manifest = json.loads(candidate.read_text(encoding="utf-8"))
                    break

            if manifest is None:
                for subdir in tmp.iterdir():
                    if subdir.is_dir():
                        for candidate in (subdir / "skill.json", subdir / "package.json"):
                            if candidate.exists():
                                manifest = json.loads(candidate.read_text(encoding="utf-8"))
                                skill_root = subdir
                                break
                        if manifest:
                            break

            skill_name = manifest.get("name", "") if manifest else zip_path.stem
            if not skill_name:
                skill_name = zip_path.stem
            skill_description = manifest.get("description", "") if manifest else ""
            skill_version = manifest.get("version", "") if manifest else ""

            safe_name = "".join(
                c if c.isalnum() or c in ("-", "_") else "_" for c in skill_name
            )
            install_dir_name = safe_name

            skills_dir = self._settings_service.get_skills_dir()
            dest = skills_dir / install_dir_name
            if dest.exists():
                shutil.rmtree(dest)
            shutil.copytree(skill_root, dest)

        now = datetime.now(timezone.utc).isoformat()
        skill_id = self._settings_service.add_skill(
            name=skill_name,
            description=skill_description,
            version=skill_version,
            file_path=file_name,
            install_dir=install_dir_name,
            installed_at=now,
        )
        return {
            "id": skill_id,
            "name": skill_name,
            "description": skill_description,
            "version": skill_version,
            "file_path": file_name,
            "install_dir": install_dir_name,
            "installed_at": now,
        }

    def delete_skill(self, skill_id: int, install_dir: str | None) -> None:
        """Remove a skill record and its installed files."""
        self._settings_service.remove_skill(skill_id)

        if install_dir:
            try:
                skills_dir = self._settings_service.get_skills_dir()
                dest = skills_dir / install_dir
                if dest.exists():
                    shutil.rmtree(dest)
            except Exception:
                pass

    def save_skill_advanced(
        self,
        skill_id: int,
        *,
        system_prompt_template: str,
        tool_allowlist: str,
        tool_denylist: str,
        model_override: str,
        temperature_override: float,
    ) -> bool:
        """Serialize and persist advanced skill settings."""
        allow_text = tool_allowlist.strip()
        allow_json_val = (
            json.dumps([t.strip() for t in allow_text.split(",") if t.strip()])
            if allow_text else None
        )
        deny_text = tool_denylist.strip()
        deny_json_val = (
            json.dumps([t.strip() for t in deny_text.split(",") if t.strip()])
            if deny_text else None
        )
        model_val = model_override.strip() or ""
        temp_val = temperature_override if temperature_override > 0 else None

        return self._settings_service.update_skill(
            skill_id,
            system_prompt_template=system_prompt_template,
            tool_allowlist_json=allow_json_val,
            tool_denylist_json=deny_json_val,
            model_override=model_val,
            temperature_override=temp_val,
        )
