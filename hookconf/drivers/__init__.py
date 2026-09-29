"""Harness drivers. Each driver writes hook config into a run root and starts the harness headless."""
from .claude_code import ClaudeCodeDriver
from .codex import CodexDriver
from .opencode import OpenCodeDriver, OpenCodeV2Driver
from .pi import PiDriver
from .warp import WarpDriver

DRIVERS = {"claude-code": ClaudeCodeDriver, "codex": CodexDriver,
           "opencode-v1": OpenCodeDriver, "opencode-v2": OpenCodeV2Driver, "warp": WarpDriver, "pi": PiDriver}


def get_driver(name: str, binary: str = None):
    try:
        return DRIVERS[name](binary)
    except KeyError:
        raise SystemExit(f"unknown harness {name!r}; known: {', '.join(sorted(DRIVERS))}")
