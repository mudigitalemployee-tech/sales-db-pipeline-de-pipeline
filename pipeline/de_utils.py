"""
de_utils.py — Shared utilities for the Data Engineering skill v2.1
===================================================================
Helpers, constants, DQ config, lineage tracker, self-check framework.
v2.1 additions:
  - PII masking (SHA256 hash + sentinel strategy)
  - Data Contracts (column-level validation rules)
  - Schema Evolution detection (new cols, removed cols, type changes)
  - Incremental / CDC support utilities
  - Anomaly detection helpers (Z-score, IQR, volume drift)
  - Realistic timing with time.time() precision
"""

import os
import json
import hashlib
import datetime
import re
import time
from pathlib import Path

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────

SKILL_DIR     = Path(__file__).parent.parent

# ─── Portable base directories ────────────────────────────────────────────────
# Resolution order (highest priority first):
#   1. CLI  → pass --artifacts-dir / --reports-dir to any phase script
#   2. Env  → DE_ARTIFACTS_DIR / DE_REPORTS_DIR environment variables
#   3. Auto → <script_dir>/de-artifacts  (works on any machine, any OS)
# ──────────────────────────────────────────────────────────────────────────────
_SCRIPT_DIR   = Path(__file__).resolve().parent           # …/scripts/
_DEFAULT_BASE = _SCRIPT_DIR / "de-artifacts"              # portable fallback

ARTIFACTS_DIR = Path(
    os.environ.get("DE_ARTIFACTS_DIR", str(_DEFAULT_BASE))
)
REPORTS_DIR = Path(
    os.environ.get("DE_REPORTS_DIR", str(_SCRIPT_DIR / "de-reports"))
)

# 5-stage outputs are stored under:
# ARTIFACTS_BASE / {project_name} / stage{N} / stage{N}_output.json
# Legacy PHASE*_DIR constants removed — 12-phase system retired.

MUSIGMA_COLORS = {
    "teal":   "#0d9488", "navy": "#1e293b", "blue": "#2563eb",
    "purple": "#7c3aed", "green": "#059669", "amber": "#d97706",
    "red":    "#dc2626", "slate": "#64748b", "bg": "#eef0f5", "white": "#ffffff",
}

DQ_THRESHOLDS = {
    "null_rate_warn":       0.05,
    "null_rate_fail":       0.20,
    "duplicate_rate_warn":  0.01,
    "duplicate_rate_fail":  0.05,
    "row_count_drift_warn": 0.10,
    "row_count_drift_fail": 0.30,
    "volume_anomaly_warn":  0.25,
    "schema_drift_fail":    True,
    "z_score_outlier":      3.0,    # Z-score threshold for numeric anomalies
    "iqr_multiplier":       1.5,    # IQR multiplier for box-plot anomalies
}

SUPPORTED_SOURCES    = ["csv", "json", "parquet", "excel", "postgres", "mysql", "snowflake", "bigquery", "sqlite", "api", "kafka", "s3", "gcs"]
ARCHITECTURE_PATTERNS = ["simple", "medallion", "lambda", "kappa"]
PIPELINE_TYPES       = ["etl", "elt", "streaming", "batch", "incremental", "full_load", "cdc"]


# ─────────────────────────────────────────────
# Directory helpers
# ─────────────────────────────────────────────

def ensure_dirs(*dirs):
    for d in dirs:
        Path(d).mkdir(parents=True, exist_ok=True)


def get_report_version(project_name: str) -> str:
    today = datetime.date.today()
    prefix = f"{project_name}-de-v{today.strftime('%y.%m.')}"
    existing = list(REPORTS_DIR.glob(f"{project_name}-de-v*.html"))
    versions = []
    for f in existing:
        m = re.search(r'v\d{2}\.\d{2}\.(\d{2})\.html$', f.name)
        if m:
            versions.append(int(m.group(1)))
    next_v = (max(versions) + 1) if versions else 1
    return f"{prefix}{next_v:02d}"


# ─────────────────────────────────────────────
# Lineage Tracker
# ─────────────────────────────────────────────

class LineageTracker:
    def __init__(self, project_name: str):
        self.project_name = project_name
        self.nodes = []
        self.links = []
        self._node_idx = {}

    def add_source(self, label: str, details: str = "") -> str:
        return self._add_node(label, "source", details)

    def add_transform(self, label: str, details: str = "") -> str:
        return self._add_node(label, "transform", details)

    def add_destination(self, label: str, details: str = "") -> str:
        return self._add_node(label, "destination", details)

    def add_link(self, from_label: str, to_label: str, rows: int = 0, label: str = ""):
        from_id = self._node_idx.get(from_label)
        to_id   = self._node_idx.get(to_label)
        if from_id is not None and to_id is not None:
            self.links.append({"source": from_id, "target": to_id, "value": max(rows, 1), "label": label or f"{rows:,} rows"})

    def _add_node(self, label: str, node_type: str, details: str) -> str:
        if label not in self._node_idx:
            idx = len(self.nodes)
            self.nodes.append({"id": idx, "label": label, "type": node_type, "details": details})
            self._node_idx[label] = idx
        return label

    def to_dict(self) -> dict:
        return {"project_name": self.project_name, "nodes": self.nodes, "links": self.links,
                "generated_at": datetime.datetime.now().isoformat()}

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


# ─────────────────────────────────────────────
#  NEW: Data Contracts
# ─────────────────────────────────────────────

# Default contract rules per semantic role / pattern
DEFAULT_CONTRACT_RULES = {
    "email": {
        "pattern": r"^[\w\.\+\-]+@[\w\-]+\.[a-zA-Z]{2,}$",
        "description": "Valid email format"
    },
    "phone": {
        "pattern": r"^\+?[\d\s\-\(\)]{7,15}$",
        "description": "Valid phone number format"
    },
    "date": {
        "pattern": r"^\d{4}-\d{2}-\d{2}$",
        "description": "ISO date format YYYY-MM-DD"
    },
    "numeric_positive": {
        "min": 0,
        "description": "Must be non-negative"
    },
    "rating": {
        "min": 1, "max": 5,
        "description": "Rating must be between 1 and 5"
    },
    "percentage": {
        "min": 0.0, "max": 100.0,
        "description": "Percentage between 0 and 100"
    },
    "score_0_1": {
        "min": 0.0, "max": 1.0,
        "description": "Score normalized between 0 and 1"
    }
}


def build_data_contracts(schema: list) -> list:
    """
    Auto-generate data contract rules from schema column names.
    Returns list of {column, rule_type, rule, description, severity}.
    """
    contracts = []
    for col_info in schema:
        col = col_info["column"].lower()
        dtype = col_info.get("dtype", "string")
        null_rate = col_info.get("null_rate", 0)

        # Not-null constraint for low-null columns
        if null_rate == 0:
            contracts.append({
                "column": col_info["column"],
                "rule_type": "NOT_NULL",
                "rule": "null_rate == 0",
                "description": "Column must not contain null values",
                "severity": "FAIL"
            })

        # Format validation for email columns
        if "email" in col:
            contracts.append({
                "column": col_info["column"],
                "rule_type": "FORMAT",
                "rule": DEFAULT_CONTRACT_RULES["email"]["pattern"],
                "description": DEFAULT_CONTRACT_RULES["email"]["description"],
                "severity": "WARN"
            })

        # Format validation for date columns
        if any(kw in col for kw in ["date", "ts", "timestamp", "created", "updated"]):
            contracts.append({
                "column": col_info["column"],
                "rule_type": "FORMAT",
                "rule": DEFAULT_CONTRACT_RULES["date"]["pattern"],
                "description": DEFAULT_CONTRACT_RULES["date"]["description"],
                "severity": "WARN"
            })

        # Range check for rating columns
        if "rating" in col:
            contracts.append({
                "column": col_info["column"],
                "rule_type": "RANGE",
                "rule": "1 <= value <= 5",
                "description": DEFAULT_CONTRACT_RULES["rating"]["description"],
                "severity": "FAIL"
            })

        # Range check for score / index columns (0 to 1)
        if any(kw in col for kw in ["score", "index", "rate", "ratio"]) and dtype == "numeric":
            contracts.append({
                "column": col_info["column"],
                "rule_type": "RANGE",
                "rule": "0 <= value <= 1",
                "description": DEFAULT_CONTRACT_RULES["score_0_1"]["description"],
                "severity": "WARN"
            })

        # Non-negative for weight, distance, revenue, amount, count
        if any(kw in col for kw in ["weight", "distance", "revenue", "amount", "count", "qty", "quantity", "price", "cost"]) and dtype == "numeric":
            contracts.append({
                "column": col_info["column"],
                "rule_type": "RANGE",
                "rule": "value >= 0",
                "description": DEFAULT_CONTRACT_RULES["numeric_positive"]["description"],
                "severity": "FAIL"
            })

    return contracts


def validate_data_contracts(rows: list, contracts: list) -> list:
    """
    Validate a list of row dicts against data contracts.
    Returns list of {column, rule_type, status, violations, violation_rate, detail}.
    """
    results = []
    for contract in contracts:
        col = contract["column"]
        rule_type = contract["rule_type"]
        severity = contract.get("severity", "WARN")
        values = [r.get(col, "") for r in rows]
        non_null = [v for v in values if v and str(v).strip() not in ("", "None", "null")]
        total = len(non_null)
        violations = 0

        if rule_type == "NOT_NULL":
            violations = sum(1 for v in values if not v or str(v).strip() in ("", "None", "null"))
            status = "FAIL" if violations > 0 else "PASS"

        elif rule_type == "FORMAT":
            pattern = contract["rule"]
            violations = sum(1 for v in non_null if not re.match(pattern, str(v).strip()))
            vrate = violations / total if total > 0 else 0
            status = "FAIL" if vrate > 0.10 else ("WARN" if vrate > 0.01 else "PASS")

        elif rule_type == "RANGE":
            rule = contract["rule"]
            for v in non_null:
                try:
                    fv = float(str(v))
                    if "0 <= value <= 1" in rule and not (0 <= fv <= 1):
                        violations += 1
                    elif "1 <= value <= 5" in rule and not (1 <= fv <= 5):
                        violations += 1
                    elif "value >= 0" in rule and fv < 0:
                        violations += 1
                except (ValueError, TypeError):
                    violations += 1
            vrate = violations / total if total > 0 else 0
            status = severity if violations > 0 else "PASS"
        else:
            status = "PASS"

        vrate = round(violations / max(total, 1) * 100, 2)
        results.append({
            "column": col,
            "rule_type": rule_type,
            "rule": contract["rule"],
            "description": contract["description"],
            "severity": severity,
            "status": status,
            "violations": violations,
            "violation_rate_pct": vrate,
            "detail": f"{violations} violations ({vrate}%)" if violations > 0 else "All values conform"
        })

    return results


# ─────────────────────────────────────────────
#  NEW: Schema Evolution Detection
# ─────────────────────────────────────────────

def detect_schema_evolution(current_schema: dict, baseline_schema: dict) -> dict:
    """
    Compare current schema against a saved baseline.
    current_schema / baseline_schema: {col_name: dtype_string}
    Returns: {new_columns, removed_columns, type_changes, status}
    """
    current_cols = set(current_schema.keys())
    baseline_cols = set(baseline_schema.keys())

    new_columns = [
        {"column": c, "dtype": current_schema[c], "severity": "WARN",
         "recommendation": f"New column '{c}' detected — update downstream models and documentation"}
        for c in (current_cols - baseline_cols)
    ]

    removed_columns = [
        {"column": c, "dtype": baseline_schema[c], "severity": "FAIL",
         "recommendation": f"Column '{c}' removed — breaking change; check all downstream consumers"}
        for c in (baseline_cols - current_cols)
    ]

    type_changes = []
    for col in (current_cols & baseline_cols):
        if current_schema[col] != baseline_schema[col]:
            severity = "FAIL" if _is_breaking_type_change(baseline_schema[col], current_schema[col]) else "WARN"
            type_changes.append({
                "column": col,
                "from_type": baseline_schema[col],
                "to_type": current_schema[col],
                "severity": severity,
                "recommendation": f"Type change '{baseline_schema[col]}' → '{current_schema[col]}' on '{col}'"
            })

    has_fails = bool(removed_columns) or any(t["severity"] == "FAIL" for t in type_changes)
    has_warns = bool(new_columns) or any(t["severity"] == "WARN" for t in type_changes)

    return {
        "new_columns": new_columns,
        "removed_columns": removed_columns,
        "type_changes": type_changes,
        "status": "FAIL" if has_fails else ("WARN" if has_warns else "PASS"),
        "summary": f"{len(new_columns)} new · {len(removed_columns)} removed · {len(type_changes)} type changes",
        "baseline_col_count": len(baseline_cols),
        "current_col_count": len(current_cols)
    }


def _is_breaking_type_change(from_type: str, to_type: str) -> bool:
    """Determine if a type change is breaking (FAIL) or safe (WARN)."""
    safe_promotions = {
        ("numeric", "string"), ("boolean", "string"),
        ("integer", "numeric"), ("integer", "float")
    }
    pair = (from_type.lower(), to_type.lower())
    return pair not in safe_promotions


def save_schema_baseline(schema: list, path: str):
    """Save current schema as baseline for future evolution checks."""
    baseline = {col["column"]: col["dtype"] for col in schema}
    with open(path, "w") as f:
        json.dump({
            "saved_at": datetime.datetime.now().isoformat(),
            "schema": baseline
        }, f, indent=2)


def load_schema_baseline(path: str) -> dict:
    """Load saved schema baseline. Returns {} if not found."""
    try:
        with open(path) as f:
            data = json.load(f)
        return data.get("schema", {})
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ─────────────────────────────────────────────
#  NEW: PII Masking
# ─────────────────────────────────────────────

PII_PATTERNS = ["email", "phone", "mobile", "ssn", "social_security", "credit_card",
                "card_number", "passport", "national_id", "address", "zip", "postal",
                "dob", "birth", "firstname", "lastname", "full_name", "customer_name",
                "first_name", "last_name", "ip_address", "ip_addr"]

MASKING_SALT = "musigma_de_v2_salt_2026"


# ─────────────────────────────────────────────────────────────────────────────
# Reasoning Engine  (replaces keyword / heuristic rules across all phases)
# ─────────────────────────────────────────────────────────────────────────────

def _get_openai_key() -> str:
    """Resolve OpenAI API key: env var → openclaw.json config."""
    key = os.environ.get("OPENAI_API_KEY", "")
    if key:
        return key
    try:
        cfg_path = Path(os.environ.get("OPENCLAW_CONFIG", str(Path.home() / ".openclaw" / "openclaw.json")))
        if cfg_path.exists():
            cfg = json.loads(cfg_path.read_text())
            key = (
                cfg.get("env", {}).get("vars", {}).get("OPENAI_API_KEY") or
                cfg.get("env", {}).get("OPENAI_API_KEY") or ""
            )
    except Exception:
        pass
    return key


def reasoning_engine(task: str, context: dict, schema: dict, fallback_fn=None):
    """
    Reasoning Engine — thinks like a senior data architect using the full BRD context.

    Replaces keyword/heuristic rules throughout the DE skill pipeline.
    Calls GPT-4o-mini with a structured prompt; returns a parsed JSON result.
    Falls back to `fallback_fn(context)` if LLM is unavailable.

    Parameters
    ----------
    task : str
        One of: "risk_analysis" | "pii_detection" | "architecture_reasoning"
    context : dict
        Free-form dict of BRD/pipeline context fields
        (domain, problem_statement, goal, source_system, pipeline_type, columns, etc.)
    schema : dict
        Expected JSON output schema description passed to the LLM
    fallback_fn : callable, optional
        Called with `context` if OpenAI is unavailable — must return same shape as schema

    Returns
    -------
    dict  — parsed LLM response matching `schema`, or fallback result
    """
    import urllib.request
    import urllib.error

    api_key = _get_openai_key()
    if not api_key:
        print("[ReasoningEngine] WARN — No OpenAI key found; using fallback heuristics.")
        return fallback_fn(context) if fallback_fn else {}

    TASK_PROMPTS = {
        "risk_analysis": (
            "You are a senior data architect reviewing a Business Requirements Document (BRD). "
            "Analyze the pipeline context below and identify ALL relevant risks and compliance flags "
            "a data architect would raise — covering regulatory (HIPAA, PCI-DSS, GDPR, SOX, etc.), "
            "technical (schema drift, volume spikes, SLA breach, data lineage gaps), "
            "operational (access control, retention, audit trail), and domain-specific risks. "
            "Think beyond surface keywords — reason about the INTENT and DATA TYPE of this pipeline. "
            "Return ONLY valid JSON matching the schema provided. No prose, no markdown fences."
        ),
        "pii_detection": (
            "You are a data privacy expert and data architect. "
            "Given a list of column names from a data pipeline, classify each column as PII or not. "
            "Reason about the column name in the context of the domain and pipeline purpose — "
            "not just keyword matching. Consider indirect identifiers (quasi-PII) as well. "
            "Return ONLY valid JSON matching the schema provided. No prose, no markdown fences."
        ),
        "architecture_reasoning": (
            "You are a senior data architect. Given the pipeline context below, recommend the "
            "optimal architecture pattern, medallion layer design, and infrastructure choices. "
            "Reason about data volume, source complexity, SLA requirements, and team maturity. "
            "Return ONLY valid JSON matching the schema provided. No prose, no markdown fences."
        ),
    }

    system_prompt = TASK_PROMPTS.get(task, TASK_PROMPTS["risk_analysis"])
    user_prompt = (
        f"PIPELINE CONTEXT:\n{json.dumps(context, indent=2)}\n\n"
        f"EXPECTED OUTPUT SCHEMA:\n{json.dumps(schema, indent=2)}\n\n"
        "Respond with ONLY the JSON object. No explanation."
    )

    payload = json.dumps({
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 1024,
        "response_format": {"type": "json_object"},
    }).encode("utf-8")

    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            raw = body["choices"][0]["message"]["content"].strip()
            result = json.loads(raw)
            print(f"[ReasoningEngine] ✅ {task} — LLM reasoning complete")
            return result
    except urllib.error.HTTPError as e:
        print(f"[ReasoningEngine] WARN — OpenAI HTTP {e.code}: {e.read().decode()}; using fallback.")
    except Exception as e:
        print(f"[ReasoningEngine] WARN — {e}; using fallback heuristics.")

    return fallback_fn(context) if fallback_fn else {}


def detect_pii_columns(df_or_cols, domain: str = "", pipeline_purpose: str = "") -> list:
    """
    Detect PII columns — LLM-powered reasoning first, keyword fallback.

    Accepts a DataFrame, list of column names, or list of column dicts.
    Returns list of column names classified as PII.
    """
    if hasattr(df_or_cols, "columns"):
        cols = list(df_or_cols.columns)
    else:
        cols = [
            c.get("name", c) if isinstance(c, dict) else c
            for c in df_or_cols
        ]

    if not cols:
        return []

    def _keyword_fallback(ctx):
        return {
            "pii_columns": [
                c for c in ctx["columns"]
                if any(p in c.lower().replace(" ", "_") for p in PII_PATTERNS)
            ]
        }

    context = {
        "columns": cols,
        "domain": domain or "unknown",
        "pipeline_purpose": pipeline_purpose or "data pipeline",
    }
    schema = {
        "pii_columns": ["list of column names that are PII or quasi-PII"],
        "reasoning": {"column_name": "brief reason why it is PII"},
    }

    result = reasoning_engine(
        task="pii_detection",
        context=context,
        schema=schema,
        fallback_fn=_keyword_fallback,
    )
    return result.get("pii_columns", [])


# detect_pii_columns — defined above with Reasoning Engine (see line ~525)


def mask_pii_column(values: list, strategy: str = "sha256", col_name: str = "") -> list:
    """
    Apply PII masking to a list of values.
    strategies:
      sha256   → deterministic hash (preserves joinability)
      redact   → replace with [REDACTED]
      sentinel → replace with fixed sentinel (e.g. MASKED_EMAIL)
      partial  → show first 2 + last 2 chars, mask middle (for names/emails)
    """
    masked = []
    for v in values:
        if not v or str(v).strip() in ("", "None", "null"):
            masked.append(v)
            continue
        sv = str(v).strip()
        if strategy == "sha256":
            salted = (MASKING_SALT + sv).encode("utf-8")
            masked.append(hashlib.sha256(salted).hexdigest()[:16])
        elif strategy == "redact":
            masked.append("[REDACTED]")
        elif strategy == "sentinel":
            masked.append(f"MASKED_{col_name.upper()[:10]}")
        elif strategy == "partial":
            if len(sv) <= 4:
                masked.append("****")
            else:
                masked.append(sv[:2] + "*" * (len(sv) - 4) + sv[-2:])
        else:
            masked.append(hashlib.sha256(sv.encode()).hexdigest()[:16])
    return masked


def apply_pii_masking(rows: list, pii_columns: list, strategy: str = "sha256") -> tuple:
    """
    Apply PII masking to all PII columns in a list of row dicts.
    Returns (masked_rows, masking_log).
    """
    masking_log = []
    rows = [dict(r) for r in rows]

    # Normalize: find actual column keys that match PII patterns
    if not rows:
        return rows, masking_log

    actual_cols = list(rows[0].keys())
    cols_to_mask = []
    for pii_col in pii_columns:
        # Direct match
        if pii_col in actual_cols:
            cols_to_mask.append(pii_col)
        else:
            # Fuzzy match (handles case/underscore differences)
            normalized_pii = pii_col.lower().replace(" ", "_")
            for ac in actual_cols:
                if ac.lower().replace(" ", "_") == normalized_pii:
                    cols_to_mask.append(ac)
                    break

    for col in cols_to_mask:
        original_sample = [rows[i].get(col, "") for i in range(min(3, len(rows)))]
        values = [r.get(col, "") for r in rows]
        masked_values = mask_pii_column(values, strategy, col)
        for i, r in enumerate(rows):
            r[col] = masked_values[i]
        masked_sample = [rows[i].get(col, "") for i in range(min(3, len(rows)))]
        masking_log.append({
            "column": col,
            "strategy": strategy,
            "rows_masked": len([v for v in values if v and str(v).strip()]),
            "original_sample": [str(s)[:20] for s in original_sample],
            "masked_sample": masked_sample,
            "note": f"PII column '{col}' masked using {strategy} strategy"
        })

    return rows, masking_log


# ─────────────────────────────────────────────
#  NEW: Incremental / CDC Support
# ─────────────────────────────────────────────

def get_incremental_watermark(watermark_path: str) -> dict:
    """Load the last watermark (timestamp or ID) for incremental loads."""
    try:
        with open(watermark_path) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"watermark": None, "type": None, "last_updated": None}


def save_incremental_watermark(watermark_path: str, watermark_value, watermark_type: str = "timestamp"):
    """Save the new watermark after a successful incremental run."""
    data = {
        "watermark": str(watermark_value),
        "type": watermark_type,
        "last_updated": datetime.datetime.now().isoformat()
    }
    with open(watermark_path, "w") as f:
        json.dump(data, f, indent=2)


def apply_incremental_filter(rows: list, watermark_col: str, last_watermark,
                              pipeline_type: str = "incremental") -> tuple:
    """
    Filter rows for incremental load — only return rows newer than last watermark.
    Returns (filtered_rows, incremental_stats).
    """
    if pipeline_type == "full_load" or not last_watermark or not watermark_col:
        return rows, {"mode": "full_load", "rows_filtered": 0, "rows_returned": len(rows)}

    filtered = []
    skipped = 0
    for r in rows:
        val = r.get(watermark_col, "")
        if not val:
            filtered.append(r)
            continue
        try:
            if str(val) > str(last_watermark):
                filtered.append(r)
            else:
                skipped += 1
        except Exception:
            filtered.append(r)

    return filtered, {
        "mode": pipeline_type,
        "watermark_column": watermark_col,
        "last_watermark": str(last_watermark),
        "rows_in_source": len(rows),
        "rows_skipped": skipped,
        "rows_returned": len(filtered),
        "new_watermark": max((r.get(watermark_col, "") for r in filtered if r.get(watermark_col)), default=last_watermark)
    }


def generate_cdc_events(old_rows: list, new_rows: list, pk_col: str) -> dict:
    """
    Compare old snapshot vs new snapshot to generate CDC events.
    Returns {inserts, updates, deletes, unchanged}.
    CDC strategies: Full snapshot diff (SCD Type 2 compatible).
    """
    old_map = {r.get(pk_col, ""): r for r in old_rows if r.get(pk_col)}
    new_map = {r.get(pk_col, ""): r for r in new_rows if r.get(pk_col)}

    old_keys = set(old_map.keys())
    new_keys = set(new_map.keys())

    inserts   = [new_map[k] for k in (new_keys - old_keys)]
    deletes   = [old_map[k] for k in (old_keys - new_keys)]
    updates   = []
    unchanged = []

    for k in (old_keys & new_keys):
        if old_map[k] != new_map[k]:
            updates.append({
                "pk": k,
                "before": old_map[k],
                "after": new_map[k],
                "changed_cols": [col for col in new_map[k] if new_map[k].get(col) != old_map[k].get(col)]
            })
        else:
            unchanged.append(k)

    return {
        "inserts": len(inserts),
        "updates": len(updates),
        "deletes": len(deletes),
        "unchanged": len(unchanged),
        "total_processed": len(new_rows),
        "insert_records": inserts,
        "update_records": updates,
        "delete_records": deletes,
        "summary": f"CDC: +{len(inserts)} inserts · ~{len(updates)} updates · -{len(deletes)} deletes · ={len(unchanged)} unchanged"
    }


def generate_partitioning_strategy(schema: list, row_count: int) -> dict:
    """Recommend a partitioning strategy based on schema and volume."""
    date_cols = [s["column"] for s in schema if s.get("dtype") == "datetime" or
                 any(kw in s["column"].lower() for kw in ["date", "ts", "created", "updated"])]
    cat_cols  = [s["column"] for s in schema if s.get("dtype") == "string" and
                 s.get("n_unique", 9999) < 50]

    if date_cols and row_count > 100_000:
        strategy = "range"
        partition_col = date_cols[0]
        granularity = "monthly" if row_count > 1_000_000 else "daily"
        reason = f"High-volume dataset with date column '{partition_col}' — range partitioning by {granularity}"
    elif cat_cols and row_count > 50_000:
        strategy = "list"
        partition_col = cat_cols[0]
        granularity = "per_value"
        reason = f"Categorical column '{partition_col}' with low cardinality — list partitioning"
    elif row_count > 500_000:
        strategy = "hash"
        partition_col = schema[0]["column"] if schema else "id"
        granularity = "8_buckets"
        reason = "High volume without clear partition key — hash partitioning for even distribution"
    else:
        strategy = "none"
        partition_col = None
        granularity = "n/a"
        reason = f"Row count ({row_count:,}) below partitioning threshold — no partitioning needed"

    return {
        "strategy": strategy,
        "partition_column": partition_col,
        "granularity": granularity,
        "reason": reason,
        "ddl_hint": f"PARTITION BY {strategy.upper()}({partition_col})" if strategy != "none" else "No partitioning"
    }


# ─────────────────────────────────────────────
#  NEW: Anomaly Detection
# ─────────────────────────────────────────────

def detect_numeric_anomalies(rows: list, schema: list) -> list:
    """
    Detect anomalies in numeric columns using Z-score and IQR methods.
    Returns list of {column, method, anomaly_count, anomaly_rate, threshold, examples}.
    """
    anomalies = []
    numeric_cols = [s["column"] for s in schema if s.get("dtype") == "numeric"]

    for col in numeric_cols:
        values = []
        for r in rows:
            v = r.get(col, "")
            if v and str(v).strip() not in ("", "None", "null"):
                try:
                    values.append(float(str(v)))
                except (ValueError, TypeError):
                    pass

        if len(values) < 10:
            continue

        # Z-score
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std = variance ** 0.5
        z_thresh = DQ_THRESHOLDS["z_score_outlier"]
        if std > 0:
            z_outliers = [v for v in values if abs((v - mean) / std) > z_thresh]
            if z_outliers:
                anomalies.append({
                    "column": col,
                    "method": "Z-Score",
                    "anomaly_count": len(z_outliers),
                    "anomaly_rate_pct": round(len(z_outliers) / len(values) * 100, 2),
                    "threshold": f"|Z| > {z_thresh}",
                    "mean": round(mean, 3),
                    "std": round(std, 3),
                    "examples": [round(v, 3) for v in sorted(z_outliers, key=abs, reverse=True)[:3]],
                    "severity": "WARN" if len(z_outliers) / len(values) < 0.05 else "FAIL"
                })

        # IQR
        sorted_vals = sorted(values)
        q1 = sorted_vals[len(sorted_vals) // 4]
        q3 = sorted_vals[3 * len(sorted_vals) // 4]
        iqr = q3 - q1
        iqr_mult = DQ_THRESHOLDS["iqr_multiplier"]
        lower = q1 - iqr_mult * iqr
        upper = q3 + iqr_mult * iqr
        iqr_outliers = [v for v in values if v < lower or v > upper]
        if iqr_outliers and len(iqr_outliers) != len(z_outliers if std > 0 else []):
            anomalies.append({
                "column": col,
                "method": "IQR",
                "anomaly_count": len(iqr_outliers),
                "anomaly_rate_pct": round(len(iqr_outliers) / len(values) * 100, 2),
                "threshold": f"< {round(lower,2)} or > {round(upper,2)}",
                "q1": round(q1, 3), "q3": round(q3, 3), "iqr": round(iqr, 3),
                "examples": [round(v, 3) for v in sorted(iqr_outliers, key=lambda x: abs(x - mean), reverse=True)[:3]],
                "severity": "WARN"
            })

    return anomalies


def detect_categorical_anomalies(rows: list, schema: list) -> list:
    """
    Detect anomalies in categorical columns:
    - Unexpected new values vs baseline
    - Sudden distribution shifts (dominant value change)
    """
    anomalies = []
    cat_cols = [s for s in schema if s.get("dtype") == "string" and s.get("n_unique", 9999) < 30]

    for col_info in cat_cols:
        col = col_info["column"]
        values = [str(r.get(col, "")).strip() for r in rows if r.get(col, "").strip()]
        if not values:
            continue

        from collections import Counter
        counts = Counter(values)
        total = len(values)
        dominant = counts.most_common(1)[0]

        # Flag if any single value dominates >80% — potential data issue
        if dominant[1] / total > 0.80 and len(counts) > 2:
            anomalies.append({
                "column": col,
                "method": "Distribution Dominance",
                "anomaly_count": dominant[1],
                "anomaly_rate_pct": round(dominant[1] / total * 100, 2),
                "threshold": ">80% dominated by one value",
                "dominant_value": dominant[0],
                "examples": [dominant[0]],
                "severity": "WARN",
                "detail": f"'{dominant[0]}' appears in {dominant[1]/total:.1%} of rows — check upstream data collection"
            })

    return anomalies


def detect_volume_anomaly(current_rows: int, baseline_rows: int, run_history: list = None) -> dict:
    """
    Detect volume anomalies vs baseline and 7-day rolling average.
    run_history: list of row counts from previous runs (newest last).
    """
    drift = (current_rows - baseline_rows) / max(baseline_rows, 1)
    warn_thresh = DQ_THRESHOLDS["volume_anomaly_warn"]

    result = {
        "current_rows": current_rows,
        "baseline_rows": baseline_rows,
        "drift_pct": round(drift * 100, 2),
        "status": "PASS",
        "method": "baseline_comparison",
        "detail": ""
    }

    if abs(drift) > warn_thresh * 2:
        result["status"] = "FAIL"
        result["detail"] = f"Volume drift {drift:.1%} exceeds ±{warn_thresh*200:.0f}% — investigate upstream"
    elif abs(drift) > warn_thresh:
        result["status"] = "WARN"
        result["detail"] = f"Volume drift {drift:.1%} exceeds ±{warn_thresh:.0%} warning threshold"
    else:
        result["detail"] = f"Volume drift {drift:.1%} within acceptable range (±{warn_thresh:.0%})"

    if run_history and len(run_history) >= 3:
        rolling_avg = sum(run_history[-7:]) / len(run_history[-7:])
        rolling_drift = (current_rows - rolling_avg) / max(rolling_avg, 1)
        result["rolling_avg"] = round(rolling_avg)
        result["rolling_drift_pct"] = round(rolling_drift * 100, 2)
        if abs(rolling_drift) > warn_thresh:
            result["status"] = max(result["status"], "WARN", key=["PASS","WARN","FAIL"].index)
            result["rolling_detail"] = f"7-day rolling drift: {rolling_drift:.1%}"

    return result


# ─────────────────────────────────────────────
# DQ Check Runner (enhanced)
# ─────────────────────────────────────────────

def run_dq_checks(df, checks: list = None, baseline: dict = None) -> list:
    """Run full DQ suite. Accepts pandas DataFrame OR list of dicts."""
    import collections

    # Handle both pandas DF and list of dicts
    if hasattr(df, 'to_dict'):
        rows = df.to_dict(orient="records")
        columns = list(df.columns)
        total_rows = len(df)
    else:
        rows = df
        columns = list(rows[0].keys()) if rows else []
        total_rows = len(rows)

    results = []

    def record(check, category, status, detail, value=None, threshold=None):
        results.append({"check": check, "category": category, "status": status,
                        "detail": detail, "value": value, "threshold": threshold})

    # 1. Null rate per column
    for col in columns:
        values = [r.get(col, "") for r in rows]
        null_count = sum(1 for v in values if not v or str(v).strip() in ("", "None", "null"))
        null_rate = null_count / total_rows if total_rows > 0 else 0
        if null_rate == 0:
            continue
        status = "PASS" if null_rate <= DQ_THRESHOLDS["null_rate_warn"] else \
                 ("WARN" if null_rate <= DQ_THRESHOLDS["null_rate_fail"] else "FAIL")
        record(f"Null Rate — {col}", "Completeness", status,
               f"{null_rate:.1%} nulls ({null_count} rows)", null_rate, DQ_THRESHOLDS["null_rate_fail"])

    # 2. Row-level completeness
    total_fields = total_rows * len(columns)
    null_fields  = sum(1 for r in rows for v in r.values() if not v or str(v).strip() in ("", "None", "null"))
    row_completeness = 1 - (null_fields / max(total_fields, 1))
    record("Row-Level Completeness", "Completeness",
           "PASS" if row_completeness >= 0.95 else "WARN",
           f"Average completeness: {row_completeness:.1%}", row_completeness, 0.95)

    # 3. Duplicate rows (using string hash of all values)
    seen = set()
    dup_count = 0
    for r in rows:
        key = tuple(str(v) for v in r.values())
        if key in seen:
            dup_count += 1
        seen.add(key)
    dup_rate = dup_count / total_rows if total_rows > 0 else 0
    status = "PASS" if dup_rate == 0 else \
             ("WARN" if dup_rate <= DQ_THRESHOLDS["duplicate_rate_warn"] else "FAIL")
    record("Duplicate Rows", "Uniqueness", status,
           f"{dup_count} duplicates ({dup_rate:.1%})", dup_rate, DQ_THRESHOLDS["duplicate_rate_fail"])

    # 4. Schema
    record("Schema — Column Count", "Validity", "PASS",
           f"{len(columns)} columns", len(columns), None)

    # 5. Row count
    record("Row Count", "Completeness",
           "PASS" if total_rows > 0 else "FAIL",
           f"{total_rows:,} rows", total_rows, 1)

    # 6. Volume vs baseline
    if baseline and "row_count" in baseline:
        baseline_rows = baseline["row_count"]
        drift = abs(total_rows - baseline_rows) / max(baseline_rows, 1)
        status = "PASS" if drift <= DQ_THRESHOLDS["row_count_drift_warn"] else \
                 ("WARN" if drift <= DQ_THRESHOLDS["row_count_drift_fail"] else "FAIL")
        record("Volume vs Baseline", "Freshness", status,
               f"Drift: {drift:.1%} ({baseline_rows:,} → {total_rows:,})", drift, DQ_THRESHOLDS["row_count_drift_fail"])

    return results


def dq_summary(results: list) -> dict:
    pass_count = sum(1 for r in results if r["status"] == "PASS")
    warn_count = sum(1 for r in results if r["status"] == "WARN")
    fail_count = sum(1 for r in results if r["status"] == "FAIL")
    total = len(results)
    score = round((pass_count / total * 100), 1) if total > 0 else 0
    return {"pass": pass_count, "warn": warn_count, "fail": fail_count, "total": total,
            "score": score, "overall": "PASS" if fail_count == 0 and warn_count <= 2 else
            ("WARN" if fail_count == 0 else "FAIL")}


# ─────────────────────────────────────────────
# Self-Check Framework
# ─────────────────────────────────────────────

class SelfCheck:
    def __init__(self, phase: str):
        self.phase = phase
        self.checks = []
        self._start = time.time()

    def check(self, name: str, condition: bool, detail: str = "", critical: bool = False):
        status = "PASS" if condition else ("FAIL" if critical else "WARN")
        elapsed = round(time.time() - self._start, 3)
        self.checks.append({"phase": self.phase, "check": name, "status": status,
                            "detail": detail, "elapsed_s": elapsed})
        icon = "[OK]" if status == "PASS" else ("[FAIL]" if status == "FAIL" else "[WARN]")
        print(f"  {icon} [{self.phase}] {name}: {detail}")

    def summary(self) -> dict:
        pass_n = sum(1 for c in self.checks if c["status"] == "PASS")
        warn_n = sum(1 for c in self.checks if c["status"] == "WARN")
        fail_n = sum(1 for c in self.checks if c["status"] == "FAIL")
        total_elapsed = round(time.time() - self._start, 3)
        return {"phase": self.phase, "checks": self.checks, "pass": pass_n,
                "warn": warn_n, "fail": fail_n, "total": len(self.checks),
                "total_elapsed_s": total_elapsed}

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump(self.summary(), f, indent=2)


# ─────────────────────────────────────────────
# Schema & Source Utilities (unchanged)
# ─────────────────────────────────────────────

def infer_column_roles(df_or_rows) -> dict:
    if hasattr(df_or_rows, "columns"):
        columns = list(df_or_rows.columns)
        def get_dtype(col): return str(df_or_rows[col].dtype)
        def get_nunique(col): return int(df_or_rows[col].nunique())
        def get_sample(col): return df_or_rows[col].dropna().head(50).tolist()
        def get_len(col): return len(df_or_rows)
    else:
        rows = df_or_rows
        columns = list(rows[0].keys()) if rows else []
        def get_dtype(col): return "object"
        def get_nunique(col): return len(set(r.get(col,"") for r in rows if r.get(col)))
        def get_sample(col): return [r.get(col,"") for r in rows[:50] if r.get(col)]
        def get_len(col): return len(rows)

    roles = {}
    for col in columns:
        col_lower = col.lower()
        if any(kw in col_lower for kw in ["_id", "id_", "uuid", "key"]):
            roles[col] = "id"
        elif any(kw in col_lower for kw in ["date", "time", "ts", "timestamp", "created", "updated"]):
            roles[col] = "timestamp"
        else:
            sample = get_sample(col)
            numeric_count = sum(1 for v in sample if re.match(r'^-?\d+\.?\d*$', str(v).strip()))
            if numeric_count > len(sample) * 0.8 and sample:
                roles[col] = "numeric_metric"
            else:
                n_unique = get_nunique(col)
                roles[col] = "categorical" if n_unique < 30 else "text"
    return roles


def load_source(source_path: str, source_type: str = "auto", **kwargs):
    """Load data from any supported source into a pandas DataFrame."""
    try:
        import pandas as pd
    except ImportError:
        raise ImportError("pandas is required. Install with: pip install pandas")

    source_lower = str(source_path).lower()
    if source_type == "auto":
        if source_lower.endswith(".csv"): source_type = "csv"
        elif source_lower.endswith(".json"): source_type = "json"
        elif source_lower.endswith(".parquet"): source_type = "parquet"
        elif source_lower.endswith((".xlsx",".xls")): source_type = "excel"
        elif source_lower.endswith(".db") or source_lower.endswith(".sqlite"): source_type = "sqlite"
        elif "postgresql://" in source_lower or "postgres://" in source_lower: source_type = "postgres"
        else: source_type = "csv"

    if source_type == "csv":
        try: return pd.read_csv(source_path, **kwargs)
        except Exception:
            chunks = pd.read_csv(source_path, chunksize=50000, **kwargs)
            return pd.concat(chunks, ignore_index=True)
    elif source_type == "json": return pd.read_json(source_path, **kwargs)
    elif source_type == "parquet": return pd.read_parquet(source_path, **kwargs)
    elif source_type == "excel": return pd.read_excel(source_path, **kwargs)
    elif source_type in ("sqlite","db"):
        import sqlite3
        conn = sqlite3.connect(source_path)
        table = kwargs.get("table"); query = kwargs.get("query")
        if query: df = pd.read_sql_query(query, conn)
        elif table: df = pd.read_sql_query(f"SELECT * FROM {table}", conn)
        else: raise ValueError("Specify --table or --query for SQLite")
        conn.close(); return df
    else:
        raise ValueError(f"Unsupported source type: {source_type}")


def apply_standard_transforms(df, null_strategy: str = "flag") -> tuple:
    """Apply standard DE transforms. Returns (transformed_df, transform_log)."""
    import pandas as pd, re as _re
    log = []
    df = df.copy()

    old_cols = list(df.columns)
    df.columns = [_re.sub(r'[^a-z0-9_]','_', c.lower().strip().replace(' ','_')) for c in df.columns]
    new_cols = list(df.columns)
    renamed = [(o,n) for o,n in zip(old_cols,new_cols) if o!=n]
    if renamed:
        log.append({"step":len(log)+1,"action":"Column Name Normalization",
                    "description":f"Normalized {len(renamed)} columns to lowercase_underscore",
                    "before":[r[0] for r in renamed[:5]],"after":[r[1] for r in renamed[:5]],
                    "rows_affected":"All rows"})

    str_cols = df.select_dtypes(include=["object"]).columns.tolist()
    for col in str_cols:
        df[col] = df[col].str.strip() if hasattr(df[col],'str') else df[col]
    if str_cols:
        log.append({"step":len(log)+1,"action":"Whitespace Strip",
                    "description":f"Stripped whitespace from {len(str_cols)} string columns",
                    "before":"Spaces present","after":"All trimmed","rows_affected":"All rows"})

    for col in df.select_dtypes(include=["object"]).columns:
        sample = df[col].dropna().head(20).astype(str)
        date_patterns = [r'^\d{4}-\d{2}-\d{2}',r'^\d{2}/\d{2}/\d{4}',r'^\d{4}/\d{2}/\d{2}']
        is_date = any(sample.str.match(p).mean() > 0.8 for p in date_patterns)
        if is_date:
            try:
                df[col] = pd.to_datetime(df[col], infer_datetime_format=True, errors='coerce')
                log.append({"step":len(log)+1,"action":f"Date Parsing — {col}",
                            "description":f"Converted '{col}' to datetime64",
                            "before":"string","after":"datetime64","rows_affected":f"{df[col].notna().sum()} rows"})
            except Exception: pass

    for col in df.select_dtypes(include=["int64"]).columns:
        if df[col].max() <= 2_147_483_647: df[col] = df[col].astype("int32")
    for col in df.select_dtypes(include=["float64"]).columns:
        df[col] = df[col].astype("float32")

    dup_count = df.duplicated().sum()
    if dup_count > 0:
        rows_before = len(df)
        df = df.drop_duplicates().reset_index(drop=True)
        log.append({"step":len(log)+1,"action":"Duplicate Removal",
                    "description":f"Removed {dup_count} exact duplicate rows",
                    "before":f"{rows_before:,} rows","after":f"{len(df):,} rows",
                    "rows_affected":f"{dup_count} rows removed"})

    null_cols = [col for col in df.columns if df[col].isna().any()]
    if null_cols:
        numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()
        if null_strategy == "flag":
            for col in null_cols:
                df[f"{col}_is_null"] = df[col].isna().astype("int8")
            log.append({"step":len(log)+1,"action":"Null Flagging",
                        "description":f"Added {len(null_cols)} _is_null indicator columns",
                        "before":"Nulls, no flag","after":f"{len(null_cols)} flags added",
                        "rows_affected":"All rows"})
        elif null_strategy == "fill_median":
            for col in numeric_cols:
                if df[col].isna().any():
                    df[col] = df[col].fillna(df[col].median())
            log.append({"step":len(log)+1,"action":"Null Fill (Median)",
                        "description":"Filled numeric nulls with column median",
                        "before":"Nulls present","after":"Filled","rows_affected":"Null cells"})
        elif null_strategy == "drop":
            rows_before = len(df)
            df = df.dropna().reset_index(drop=True)
            log.append({"step":len(log)+1,"action":"Null Row Drop",
                        "description":f"Dropped all rows with any null",
                        "before":f"{rows_before:,}","after":f"{len(df):,}",
                        "rows_affected":f"{rows_before-len(df)} removed"})

    return df, log


def recommend_architecture(source_count=1, row_count=0, has_streaming=False, has_multiple_layers=False) -> dict:
    if has_streaming and has_multiple_layers: pattern, reason = "lambda", "Hybrid batch+streaming → Lambda"
    elif has_streaming: pattern, reason = "kappa", "Stream-first → Kappa"
    elif has_multiple_layers or row_count > 5_000_000 or source_count > 3:
        pattern, reason = "medallion", f"Scale/complexity → Medallion (Bronze→Silver→Gold)"
    else: pattern, reason = "simple", "Single source, moderate volume → Simple ETL"
    desc = {"simple":"Source→Extract→Transform→Load","medallion":"Bronze→Silver→Gold",
            "lambda":"Batch+Speed→Serving","kappa":"Streams→Processing→Serving"}
    layers = {"medallion":["bronze","silver","gold"],"lambda":["batch","speed","serving"],
              "kappa":["stream","serving"],"simple":["extract","transform","load"]}
    return {"recommended":pattern,"reason":reason,"description":desc[pattern],"layers":layers[pattern]}


def json_safe(obj):
    import numpy as np, pandas as pd
    if isinstance(obj, (np.integer,)): return int(obj)
    if isinstance(obj, (np.floating,)): return float(obj)
    if isinstance(obj, (np.ndarray,)): return obj.tolist()
    if isinstance(obj, pd.Timestamp): return obj.isoformat()
    if isinstance(obj, datetime.datetime): return obj.isoformat()
    if isinstance(obj, datetime.date): return obj.isoformat()
    raise TypeError(f"Not JSON serializable: {type(obj)}")


def get_project_artifact_dir(project_name: str, phase: str) -> Path:
    """FIX #5 — return a project-scoped artifact directory to prevent cross-run contamination.

    Canonical path: artifacts/<phase>/<project_name>/
    Falls back to the legacy shared path (artifacts/<phase>/) when project_name is empty,
    so existing code that doesn't pass a name still works.
    """
    if not project_name:
        return ARTIFACTS_DIR / phase
    safe_name = sanitise_project_name(project_name)
    path = ARTIFACTS_DIR / phase / safe_name
    path.mkdir(parents=True, exist_ok=True)
    return path


def sanitise_project_name(name: str) -> str:
    """Sanitise project_name to be safe for file paths, Python identifiers, and GitHub repo names.

    Rules applied:
    - Strip leading/trailing whitespace
    - Replace spaces, hyphens, and special chars with underscores (Python/file safe)
    - Lowercase everything
    - Collapse multiple underscores into one
    - Remove any character not in [a-z0-9_]
    - Strip leading/trailing underscores
    - Truncate to 50 characters (GitHub repo name limit is 100, keep headroom)

    Usage: call this at the top of every phase script's main() before using args.project_name.
    """
    import re
    s = name.strip().lower()
    s = re.sub(r"[\s\-\.]+", "_", s)       # spaces / hyphens / dots → underscore
    s = re.sub(r"[^a-z0-9_]", "", s)       # remove all non-alphanumeric/underscore chars
    s = re.sub(r"_+", "_", s)              # collapse consecutive underscores
    s = s.strip("_")                        # strip leading/trailing underscores
    s = s[:50]                              # truncate
    if not s:
        raise ValueError(f"project_name '{name}' is invalid — must contain at least one alphanumeric character.")
    return s


print("[de_utils v2.2] Loaded — DE skill utilities with CDC, Schema Evolution, PII Masking, Data Contracts, Anomaly Detection, project_name sanitisation")
