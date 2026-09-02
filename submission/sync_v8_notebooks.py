from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "attack_v8.py"
OUTPUTS = {
    "public": ROOT / "aisec_v8_public.ipynb",
    "private": ROOT / "aisec_v8_private.ipynb",
}


def _source_for_mode(mode: str) -> str:
    source = SOURCE.read_text()
    source, replacements = re.subn(r'^MODE = "public"', f'MODE = "{mode}"', source, count=1, flags=re.M)
    if replacements != 1:
        raise RuntimeError("expected exactly one public MODE assignment in attack_v8.py")
    return source


def _server_cell() -> str:
    return (
        "import os\n"
        "if not os.getenv('KAGGLE_IS_COMPETITION_RERUN'):\n"
        "    os.environ['AICOMP_MODEL_NAMES'] = 'deterministic'\n\n"
        "from kaggle_evaluation.jed_attack_134815.jed_attack_inference_server import "
        "JEDAttackInferenceServer\n"
        "JEDAttackInferenceServer().run()\n"
    )


def _notebook(mode: str) -> dict:
    source = _source_for_mode(mode)
    digest = hashlib.sha256(source.encode()).hexdigest()
    cell1 = (
        f"# === Cell 1: write attack.py (v8 {mode}) ===\n"
        f"attack_src = {source!r}\n"
        "with open('/kaggle/working/attack.py', 'w') as f:\n"
        "    f.write(attack_src)\n"
        f"print('v8 {mode} written:', len(attack_src))\n"
    )
    return {
        "cells": [
            {
                "cell_type": "markdown",
                "id": f"v8-{mode}-title",
                "metadata": {},
                "source": f"# AI Agent Security v8 ({mode} slot)\n",
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "id": f"v8-{mode}-write-attack",
                "metadata": {},
                "outputs": [],
                "source": cell1,
            },
            {
                "cell_type": "code",
                "execution_count": None,
                "id": f"v8-{mode}-serve",
                "metadata": {},
                "outputs": [],
                "source": _server_cell(),
            },
        ],
        "metadata": {
            "aicomp_attack_v8_sha256": digest,
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3.11"},
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def _dump(nb: dict) -> str:
    return json.dumps(nb, ensure_ascii=False, indent=1, sort_keys=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync v8 Kaggle notebooks from attack_v8.py.")
    parser.add_argument("--write", action="store_true", help="rewrite stale notebooks")
    parser.add_argument("--check", action="store_true", help="fail if generated notebooks differ")
    args = parser.parse_args()

    if not args.write and not args.check:
        parser.error("choose --write or --check")

    failed = False
    for mode, path in OUTPUTS.items():
        expected = _dump(_notebook(mode))
        actual = path.read_text() if path.exists() else ""
        if actual == expected:
            print(f"ok {path.relative_to(ROOT.parent)}")
            continue
        if args.write:
            path.write_text(expected)
            print(f"wrote {path.relative_to(ROOT.parent)}")
        if args.check:
            failed = True
            print(f"stale {path.relative_to(ROOT.parent)}")
            for line in difflib.unified_diff(
                actual.splitlines(),
                expected.splitlines(),
                fromfile=str(path),
                tofile=f"generated/{path.name}",
                n=2,
                lineterm="",
            ):
                print(line)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
