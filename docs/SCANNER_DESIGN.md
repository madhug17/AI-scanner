# Scanner Engine & Sandboxing Design Document

## 1. Zero-Execution Sandboxing Architecture

Scanning untrusted source-code repositories introduces profound security risks:
- Malicious `setup.py` / `__init__.py` files executing arbitrary shell commands upon import.
- Symlink traversal attacks (`/etc/passwd` linking).
- Resource exhaustion (zip bombs, multi-gigabyte file allocations).

### Defense-in-Depth Implementation

```
[ Incoming Git URL ]
        │
        ▼ (SSRF & Host validation)
[ GitHub URL Validator ]
        │
        ▼ (Shallow clone: depth=1, timeouts, isolated tmpdir)
[ Safe Cloner ] ───► Temporary Sandbox Dir (/tmp_scans/<uuid>)
        │
        ▼ (Size check: <=5MB, path traversal check)
[ File Discovery ] ───► Filtered Source Tree
        │
        ▼ (Pure Lexical / AST Static Analysis — ZERO code execution)
[ Rule Engine ]
 ├── Built-in 52 AST & Regex Rules
 └── External Adapters (Semgrep, Gitleaks, pip-audit)
        │
        ▼ (Mask secrets, compute 0-100 score)
[ Result Normalizer & Scorer ]
        │
        ▼ (Immediate disk cleanup)
[ Sandbox Teardown ] ───► Delete /tmp_scans/<uuid>
```

---

## 2. Risk Scoring Formula

Risk scores range continuously from **0.0 (Clean)** to **100.0 (Critical Risk)**:

$$\text{Raw Score} = \sum_{f \in \text{Findings}} (\text{Weight}(f.\text{severity}) \times \text{ConfidenceMultiplier}(f.\text{status}))$$

$$\text{Risk Score} = \min(100.0, \, \text{round}(\text{Raw Score} \times 2.0, 1))$$

### Weights & Multipliers
- **Severity Weights**:
  - `Critical`: 10
  - `High`: 7
  - `Medium`: 4
  - `Low`: 1
  - `Info`: 0
- **Confidence Multipliers**:
  - `Confirmed`: 1.0
  - `Potential`: 0.6
  - `Needs Verification`: 0.3

### Classification Thresholds
- `0.0`: Clean
- `0.1` – `20.0`: Low Risk
- `20.1` – `50.0`: Medium Risk
- `50.1` – `75.0`: High Risk
- `75.1` – `100.0`: Critical Risk
