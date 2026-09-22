#!/usr/bin/env python3
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

library_json = json.loads((ROOT / "library.json").read_text(encoding="utf-8"))
properties = (ROOT / "library.properties").read_text(encoding="utf-8")

match = re.search(r"^version=(.+)$", properties, re.MULTILINE)
if match is None:
    raise SystemExit("library.properties has no version")

if library_json["version"] != match.group(1).strip():
    raise SystemExit("library.json and library.properties versions differ")

print(f"Scout version is consistent: {library_json['version']}")
