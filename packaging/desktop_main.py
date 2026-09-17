"""PyInstaller entry point for the ATPTmaster desktop app.

Kept tiny on purpose: all logic lives in atpt/desktop.py so it stays unit-tested
and importable. This module only exists to be the frozen executable's start.
"""
from atpt.desktop import launch

if __name__ == "__main__":
    raise SystemExit(launch())
