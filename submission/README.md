# Submission artifacts

This directory contains the final v8 release, its generated Kaggle notebooks, and historical submission variants from the **AI Agent Security — Multi-Step Tool Attacks** competition.

## Canonical v8 release

| File | Role |
|---|---|
| `attack_v8.py` | Source of truth; defaults to public mode |
| `aisec_v8_public.ipynb` | Generated public-mode notebook |
| `aisec_v8_private.ipynb` | Generated private-mode notebook |
| `sync_v8_notebooks.py` | Writes or checks notebooks against `attack_v8.py` |
| `validate_v8_release.py` | Runs structural and contract-level release validation |

Do not edit the v8 notebooks by hand. Change `attack_v8.py`, then regenerate both notebooks:

```bash
python3 submission/sync_v8_notebooks.py --write
python3 submission/sync_v8_notebooks.py --check
PYTHONPATH=comp python3 submission/validate_v8_release.py
```

The validator checks that:

- the notebook topology and launch cell are valid;
- each embedded source hash matches the notebook metadata;
- public and private notebooks differ only in their intended mode;
- generated candidates obey SDK message-count and message-length limits;
- public URLs remain under the reserved `.invalid` namespace;
- both modes return a valid fallback candidate when probes do not fire.

## Historical artifacts

The remaining `attack*.py` and `aisec_*.ipynb` files document earlier strategies and final-slot experiments. They are preserved for reproducibility, but they are not the canonical v8 release.

See the [root README](../README.md) for the competition result, architecture, repository map, and complete validation workflow.
