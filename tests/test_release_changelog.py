#!/usr/bin/env python3

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_release_changelog.py"

spec = importlib.util.spec_from_file_location("generate_release_changelog", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

assert module._resolve_commit_limit("", None) is None
assert module._resolve_commit_limit("v0.1.0", None) == 100
assert module._resolve_commit_limit("", 250) == 250
assert module._resolve_commit_limit("", 0) == 1

captured = []


def fake_require_git(args, _error_message):
    captured.append(args)
    return "abc123\tfeat: initial release"


module._require_git = fake_require_git

commits = module._resolve_commits("HEAD", None)
assert commits == [("abc123", "feat: initial release")]
assert all(not arg.startswith("--max-count=") for arg in captured[-1])

module._resolve_commits("v0.1.0..HEAD", 100)
assert "--max-count=100" in captured[-1]

print("release changelog limit behavior is correct")
