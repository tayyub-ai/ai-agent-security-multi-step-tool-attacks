from __future__ import annotations

import ast
import hashlib
import json
import sys
import types
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SUBMISSION = ROOT / "submission"
COMP = ROOT / "comp"
SOURCE = SUBMISSION / "attack_v8.py"
NOTEBOOKS = {
    "public": SUBMISSION / "aisec_v8_public.ipynb",
    "private": SUBMISSION / "aisec_v8_private.ipynb",
}
MAX_REPLAY_MESSAGES_PER_FINDING = 32


def _fail(message: str) -> None:
    raise SystemExit(f"release validation failed: {message}")


def _load_module_from_source(source: str, name: str) -> Any:
    module = types.ModuleType(name)
    module.__file__ = f"<{name}>"
    sys.modules[name] = module
    exec(compile(source, module.__file__, "exec"), module.__dict__)
    return module


def _validate_candidate_messages(candidate: Any, index: int) -> tuple[str, ...]:
    from aicomp_sdk.core.env.api import MAX_USER_MESSAGE_CHARS

    try:
        messages = tuple(candidate.user_messages)
    except TypeError as err:
        raise TypeError(f"AttackCandidate[{index}].user_messages must be iterable") from err

    if not messages:
        raise ValueError(f"AttackCandidate[{index}] must include at least one user message")
    if len(messages) > MAX_REPLAY_MESSAGES_PER_FINDING:
        raise ValueError(
            f"AttackCandidate[{index}] exceeds max chain length "
            f"({MAX_REPLAY_MESSAGES_PER_FINDING})"
        )
    for msg_idx, message in enumerate(messages):
        if not isinstance(message, str):
            raise TypeError(f"AttackCandidate[{index}].user_messages[{msg_idx}] must be a string")
        if not message.strip():
            raise ValueError(f"AttackCandidate[{index}].user_messages[{msg_idx}] cannot be empty")
        if len(message) > MAX_USER_MESSAGE_CHARS:
            raise ValueError(
                f"AttackCandidate[{index}].user_messages[{msg_idx}] exceeds max length "
                f"({MAX_USER_MESSAGE_CHARS})"
            )
    return messages


def _embedded_attack_source(path: Path) -> str:
    notebook = json.loads(path.read_text())
    code_cells = [cell for cell in notebook.get("cells", []) if cell.get("cell_type") == "code"]
    if len(code_cells) != 2:
        _fail(f"{path.name} should have exactly two code cells")

    assignment = ast.parse(code_cells[0].get("source", ""))
    first = assignment.body[0] if assignment.body else None
    if not isinstance(first, ast.Assign):
        _fail(f"{path.name} first code cell must assign attack_src")
    if not first.targets or not isinstance(first.targets[0], ast.Name):
        _fail(f"{path.name} first code cell must assign a plain name")
    if first.targets[0].id != "attack_src":
        _fail(f"{path.name} first code cell assigns {first.targets[0].id}, not attack_src")

    try:
        source = ast.literal_eval(first.value)
    except (TypeError, ValueError, SyntaxError) as err:
        _fail(f"{path.name} attack_src is not a literal string: {err}")
    if not isinstance(source, str):
        _fail(f"{path.name} attack_src is not a string")

    serve_source = code_cells[1].get("source", "")
    if "JEDAttackInferenceServer().run()" not in serve_source:
        _fail(f"{path.name} does not launch JEDAttackInferenceServer")

    digest = hashlib.sha256(source.encode()).hexdigest()
    recorded = notebook.get("metadata", {}).get("aicomp_attack_v8_sha256")
    if recorded != digest:
        _fail(f"{path.name} metadata hash mismatch")
    return source


def _check_messages(module: Any, mode: str) -> None:
    from aicomp_sdk.attacks import AttackCandidate, AttackRunConfig
    from aicomp_sdk.core.env.api import MAX_USER_MESSAGE_CHARS

    if not issubclass(module.AttackAlgorithm, module.AttackAlgorithmBase):
        _fail(f"{mode} AttackAlgorithm does not inherit AttackAlgorithmBase")

    for pack_size in range(1, module.HOPS + 1):
        for forged in (False, True):
            if mode == "public":
                messages = module._exfil_pack(100 + pack_size, pack_size, forged)
                text = messages[0]
                if "benchmark.invalid" not in text:
                    _fail("public pack does not use benchmark.invalid endpoints")
                if ".com/" in text or ".net/" in text or ".org/" in text:
                    _fail("public pack leaked a non-reserved endpoint")
            else:
                messages = module._cd_pack(100 + pack_size, pack_size, forged)
            if len(messages) != 1:
                _fail(f"{mode} pack returned {len(messages)} messages")
            if not messages[0].strip():
                _fail(f"{mode} pack returned a blank message")
            if len(messages[0]) > MAX_USER_MESSAGE_CHARS:
                _fail(f"{mode} pack exceeds SDK message limit")

    if mode == "public":
        packed = module._exfil_pack(1, 1, False)
    else:
        packed = module._cd_pack(1, 1, False)
    candidate = AttackCandidate.from_messages(packed)
    _validate_candidate_messages(candidate, 0)

    class EmptyEnv:
        def reset(self) -> None:
            self.trace = {"tool_events": []}

        def interact(self, message: str, max_tool_hops: int) -> None:
            self.trace["last_message"] = message
            self.trace["max_tool_hops"] = max_tool_hops

        def export_trace_dict(self) -> dict[str, Any]:
            return self.trace

    attack = module.AttackAlgorithm({"mode": mode, "fill_to": 8, "probe_repeats": 1})
    candidates = attack.run(EmptyEnv(), AttackRunConfig(time_budget_s=1, max_steps=1))
    if not candidates:
        _fail(f"{mode} run returned no candidates")
    if len(candidates) > module.MAX_CANDIDATES:
        _fail(f"{mode} run exceeded MAX_CANDIDATES")
    for idx, item in enumerate(candidates):
        if not isinstance(item, AttackCandidate):
            _fail(f"{mode} candidate {idx} is not AttackCandidate")
        _validate_candidate_messages(item, idx)


def main() -> int:
    sys.path.insert(0, str(COMP))
    baseline = SOURCE.read_text()
    if 'MODE = "public"' not in baseline:
        _fail("attack_v8.py must remain the public-mode source of truth")

    for mode, path in NOTEBOOKS.items():
        source = _embedded_attack_source(path)
        if f'MODE = "{mode}"' not in source:
            _fail(f"{path.name} does not embed MODE={mode!r}")
        if source != baseline.replace('MODE = "public"', f'MODE = "{mode}"', 1):
            _fail(f"{path.name} is not synchronized with attack_v8.py")
        module = _load_module_from_source(source, f"attack_v8_{mode}_release")
        _check_messages(module, mode)
        digest = hashlib.sha256(source.encode()).hexdigest()
        print(f"ok {path.relative_to(ROOT)} sha256={digest}")

    print("v8 release validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
