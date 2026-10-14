# Tools and Dependencies Log

The brief requires every tool and dependency used in building pyroXD to be
documented. This is that log. The guiding rule: **no proprietary vendor, no
paid license, no external AI service, no telemetry** — only permissively
licensed, open components, kept to the minimum.

## Runtime dependencies

| Dependency | Version used | License | Why it is here | Could we avoid it? |
|---|---|---|---|---|
| Python | 3.13 | PSF | Implementation language; cross-platform (Windows/macOS) | No — it is the runtime |
| numpy | 2.5.x | BSD-3-Clause | Vectorised linear algebra for the tree ensemble and feature maths | Possible but far slower and more error-prone; numpy is the de-facto standard, permissively licensed, no vendor lock-in |

That is the entire runtime dependency set. In particular there is **no**
scikit-learn, no TensorFlow/PyTorch, no proprietary SIEM SDK, and no network of
external services. The Half-Space Trees, EWMA, entropy detectors, calibration,
and fusion are all implemented from scratch in this repository.

## Standard-library components used

- `dataclasses` — the `FlowRecord` and `Alert` models.
- `collections.deque` / `Counter` — the entropy detector's sliding window.
- `math` — scalar logs/logistics in calibration.
- `argparse` — the CLI.
- `abc` — the detector contract.

## Development / verification tools

| Tool | Purpose | Notes |
|---|---|---|
| Plain-assert test modules | Unit + end-to-end tests | Written to run with bare `python3`; also pytest-compatible, so **pytest is optional, not required** |
| `git` | Version control | — |

## Dependency policy

1. A new runtime dependency is added only if re-implementing it would be
   *less* safe or correct than using a mature, permissively licensed library
   (the numpy rule).
2. Every dependency must be installable offline from public package indexes
   with no account, license key, or vendor relationship.
3. No dependency may phone home. pyroXD performs no outbound network calls of
   its own.
4. This log is updated in the same change that adds or removes a dependency.

## Reproducing the environment

```bash
python -m pip install -r requirements.txt   # numpy only
PYTHONPATH=src python -m pyroxd demo
```
