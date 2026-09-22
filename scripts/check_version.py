#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


def properties_version(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("version="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(f"{path}: missing version property")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", default="", help="Optional release tag, such as v0.1.0")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    manifest_version = json.loads((root / "library.json").read_text(encoding="utf-8"))["version"]
    arduino_version = properties_version(root / "library.properties")
    readme = (root / "README.md").read_text(encoding="utf-8")

    errors: list[str] = []
    if manifest_version != arduino_version:
        errors.append(
            f"library.json is {manifest_version}, but library.properties is {arduino_version}"
        )
    if not re.search(rf"\b{re.escape(manifest_version)}\b", readme):
        errors.append(f"README.md does not mention version {manifest_version}")

    if args.tag:
        expected_tag = f"v{manifest_version}"
        if args.tag != expected_tag:
            errors.append(f"release tag is {args.tag}, expected {expected_tag}")

    if errors:
        raise SystemExit("\n".join(errors))
    print(f"Scout version metadata is consistent: {manifest_version}")


if __name__ == "__main__":
    main()
