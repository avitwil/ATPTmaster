"""Discover modules from modules/*/module.json and load their entrypoints."""
from __future__ import annotations
import importlib.machinery
import importlib.util
import sys
from pathlib import Path

from .module import Manifest, Module


def discover(modules_dir: Path, project_dir: Path) -> dict[str, Module]:
    modules: dict[str, Module] = {}
    for man_path in sorted(Path(modules_dir).glob("*/module.json")):
        man = Manifest.from_file(man_path)
        man.validate()
        if not man.enabled:
            continue
        cls = _load_entrypoint(man_path.parent, man.entrypoint)
        modules[man.id] = cls(man, project_dir)
    return modules


def _load_entrypoint(mod_dir: Path, entrypoint: str):
    file_part, _, cls_name = entrypoint.partition(":")
    cls_name = cls_name or "Module"
    if not file_part.endswith(".py"):
        file_part += ".py"
    pyfile = mod_dir / file_part
    # Register the module folder as a package (with the folder on its search
    # path) BEFORE loading the entrypoint, so a multi-file module can use
    # relative imports (`from .guard import ...`). Single-file modules are
    # unaffected — they only import from `atpt.*` (absolute).
    pkg_name = f"atpt_mod_{mod_dir.name}"
    if pkg_name not in sys.modules:
        pkg_spec = importlib.machinery.ModuleSpec(pkg_name, loader=None, is_package=True)
        pkg_spec.submodule_search_locations = [str(mod_dir)]
        sys.modules[pkg_name] = importlib.util.module_from_spec(pkg_spec)
    sub_name = f"{pkg_name}.{file_part[:-3]}"
    spec = importlib.util.spec_from_file_location(sub_name, pyfile)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {pyfile}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[sub_name] = module
    spec.loader.exec_module(module)
    return getattr(module, cls_name)
