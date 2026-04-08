"""
Stage 2 — Solution Design & Architecture
Reads Stage 1 real schema and builds: architecture design, STM, DDL, layer definitions.
GATE: stage1_output.json must exist and be complete.
Zero hallucination — all column names from real schema only.
"""
import argparse
import json
import os
import sys
import csv
import time

ARTIFACTS_BASE = os.environ.get("DE_ARTIFACTS_BASE", "/home/node/Music/de-artifacts")

REQUIRED_STAGE1_FIELDS = ["source_type", "total_rows", "columns", "schema", "purpose", "project_name"]

ARCHITECTURE_PATTERNS = {
    "medallion": {
        "layers": ["bronze", "silver", "gold"],
        "description": "Bronze (raw) → Silver (cleaned/conformed) → Gold (aggregated/business-ready)",
        "best_for": "Analytics, BI dashboards, reporting, large datasets with complex transformations",
    },
    "simple": {
        "layers": ["raw", "transformed"],
        "description": "Direct ETL — raw ingestion → transformed output",
        "best_for": "Small datasets, quick one-off pipelines, simple reporting with minimal transformations",
    },
    "lambda": {
        "layers": ["bronze", "silver", "gold", "speed"],
        "description": "Medallion + real-time speed layer for low-latency queries",
        "best_for": "Real-time dashboards, fraud detection, live monitoring alongside batch analytics",
    },
    "kappa": {
        "layers": ["stream", "serving"],
        "description": "Pure streaming — events → serving layer (Kafka-native)",
        "best_for": "Pure streaming use cases: IoT, clickstream, real-time event processing with no batch requirement",
    },
}


def recommend_architecture(stage1):
    """
    Intelligently recommend architecture pattern based on:
    - Data volume (row count)
    - Source type
    - Business purpose keywords
    - Column types (date, numeric, PII presence)
    - Duplicate rate
    - Number of columns
    """
    purpose = (stage1.get("purpose") or "").lower()
    source_type = (stage1.get("source_type") or "csv").lower()
    total_rows = stage1.get("total_rows", 0)
    num_cols = stage1.get("num_columns", 0)
    dup_pct = stage1.get("duplicate_pct", 0)
    pii_cols = stage1.get("pii_columns", [])
    schema = stage1.get("schema", {})
    null_summary = stage1.get("null_summary", {})

    # Count numeric vs text columns
    numeric_types = {"int64", "int32", "float64", "float32"}
    numeric_cols = sum(1 for m in schema.values() if m.get("dtype") in numeric_types)
    has_date_cols = any(
        "date" in col.lower() or "time" in col.lower()
        for col in schema.keys()
    )
    has_pii = len(pii_cols) > 0
    has_nulls = len(null_summary) > 0
    high_dup = dup_pct > 2.0

    # Scoring signals
    scores = {"medallion": 0, "simple": 0, "lambda": 0, "kappa": 0}
    reasons = []

    # Streaming signals → kappa or lambda
    streaming_keywords = ["kafka", "stream", "real-time", "realtime", "live", "iot", "event", "clickstream"]
    if source_type == "kafka" or any(kw in purpose for kw in streaming_keywords):
        if any(kw in purpose for kw in ["batch", "daily", "report", "dashboard", "analytics"]):
            scores["lambda"] += 4
            reasons.append("Mixed batch + streaming purpose detected → Lambda pattern")
        else:
            scores["kappa"] += 4
            reasons.append("Pure streaming source/purpose detected → Kappa pattern")

    # Analytics / BI / dashboard signals → medallion
    analytics_keywords = [
        "dashboard", "report", "analytics", "bi ", "business intelligence",
        "kpi", "roi", "revenue", "performance", "analysis", "trend",
        "segmentation", "campaign", "marketing", "sales", "finance"
    ]
    analytics_hits = sum(1 for kw in analytics_keywords if kw in purpose)
    if analytics_hits >= 2:
        scores["medallion"] += analytics_hits
        reasons.append(f"Strong analytics/BI intent detected ({analytics_hits} keywords matched) → Medallion pattern")
    elif analytics_hits == 1:
        scores["medallion"] += 1

    # Data volume signals
    if total_rows > 500000:
        scores["medallion"] += 3
        reasons.append(f"Large dataset ({total_rows:,} rows) benefits from layered Medallion architecture")
    elif total_rows > 50000:
        scores["medallion"] += 2
        reasons.append(f"Medium dataset ({total_rows:,} rows) → Medallion recommended")
    elif total_rows < 5000:
        scores["simple"] += 2
        reasons.append(f"Small dataset ({total_rows:,} rows) → Simple ETL may be sufficient")

    # Column richness signals
    if num_cols > 20:
        scores["medallion"] += 2
        reasons.append(f"Wide schema ({num_cols} columns) benefits from STM and layered cleaning")
    if numeric_cols >= 5:
        scores["medallion"] += 1
        reasons.append(f"{numeric_cols} numeric columns → aggregation in Gold layer adds value")

    # Data quality signals
    if has_pii:
        scores["medallion"] += 2
        reasons.append(f"PII detected in {len(pii_cols)} column(s) → Silver masking layer required")
    if has_nulls:
        scores["medallion"] += 1
        reasons.append("Null values present → Silver cleaning layer recommended")
    if high_dup:
        scores["medallion"] += 1
        reasons.append(f"Duplicate rate {dup_pct}% → deduplication in Silver layer needed")
    if has_date_cols:
        scores["medallion"] += 1
        reasons.append("Date columns present → temporal partitioning in Gold layer beneficial")

    # Source type signals
    if source_type in ("snowflake", "bigquery", "postgresql", "mysql"):
        scores["medallion"] += 1
        reasons.append(f"Database source ({source_type}) → structured pipeline with clear layers")
    if source_type in ("rest_api", "kafka"):
        scores["lambda"] += 1
        reasons.append(f"API/streaming source → consider Lambda for real-time + batch combination")

    # Pick winner
    winner = max(scores, key=lambda k: scores[k])

    # If scores are tied or all zero → default to medallion for any analytics purpose
    if scores[winner] == 0 or (list(scores.values()).count(scores[winner]) > 1):
        winner = "medallion"
        reasons.append("Default to Medallion as the most versatile and widely used pattern")

    confidence = "HIGH" if scores[winner] >= 4 else "MEDIUM" if scores[winner] >= 2 else "LOW"

    return {
        "recommended_pattern": winner,
        "confidence": confidence,
        "scores": scores,
        "reasons": reasons[:5],
        "description": ARCHITECTURE_PATTERNS[winner]["description"],
        "best_for": ARCHITECTURE_PATTERNS[winner].get("best_for", ""),
    }


NULL_STRATEGIES = {
    "drop": "Drop rows where this column is null",
    "fill_zero": "Fill numeric nulls with 0",
    "fill_unknown": "Fill string nulls with 'UNKNOWN'",
    "fill_mean": "Fill numeric nulls with column mean",
    "flag": "Keep null, add _is_null indicator column",
    "sentinel": "Fill with sentinel value (-1 for numeric, 'N/A' for string)",
}


def gate_check(project_name):
    stage1_path = os.path.join(ARTIFACTS_BASE, project_name, "stage1", "stage1_output.json")
    if not os.path.exists(stage1_path):
        print(
            "\n❌ Stage 2 BLOCKED.\n"
            f"Stage 1 output not found at: {stage1_path}\n"
            "Please complete Stage 1 first.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(stage1_path) as f:
        stage1 = json.load(f)

    missing = [field for field in REQUIRED_STAGE1_FIELDS if not stage1.get(field)]
    if missing:
        print(
            "\n❌ Stage 2 BLOCKED.\n"
            f"Stage 1 is incomplete. Missing fields: {missing}\n"
            "Please complete Stage 1 first.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    return stage1


def infer_null_strategy(col_name, dtype, null_pct, cardinality_pct=0.0):
    """
    Infer the null-handling strategy for a column.
    A column is treated as a true primary key (PK) only if:
      - its name contains 'id' or 'key', AND
      - its cardinality is ≥80% of total rows (near-unique).
    PK columns get ffill→bfill→drop; all others use fill or flag strategies.
    Analytical dimension columns that happen to contain 'id'/'key' but have
    low cardinality are NOT treated as primary keys.
    """
    col_lower = col_name.lower()
    if null_pct == 0:
        return "none_needed"
    is_true_pk = ("id" in col_lower or "key" in col_lower) and cardinality_pct >= 0.80
    if is_true_pk:
        return "ffill_bfill_else_drop"
    if dtype in ("int64", "float64", "int32", "float32"):
        if null_pct < 5:
            return "fill_mean"
        return "fill_zero"
    if dtype == "object":
        if null_pct < 10:
            return "fill_unknown"
        return "flag"
    return "flag"


def build_stm(stage1, scd_type, join_keys, null_strategy_override):
    schema = stage1["schema"]
    pii_columns = stage1.get("pii_columns", [])
    total_rows = stage1.get("total_rows", 1) or 1
    stm_rows = []

    for col, meta in schema.items():
        dtype = meta["dtype"]
        null_pct = meta["null_pct"]
        cardinality = meta.get("cardinality", 0)
        cardinality_pct = cardinality / total_rows
        is_pii = col in pii_columns
        is_key = col in join_keys

        silver_transform = "pass_through"
        if is_pii:
            silver_transform = "SHA256_hash"
        elif null_pct > 0:
            strategy = null_strategy_override if null_strategy_override else infer_null_strategy(
                col, dtype, null_pct, cardinality_pct
            )
            silver_transform = f"null_handle:{strategy}"

        silver_col = col
        gold_col = col if not is_pii else f"{col}_masked"

        stm_rows.append({
            "source_column": col,
            "source_dtype": dtype,
            "silver_column": silver_col,
            "silver_transform": silver_transform,
            "gold_column": gold_col,
            "is_pii": is_pii,
            "is_key": is_key,
            "null_pct": null_pct,
            "scd_type": scd_type if is_key else "n/a",
        })

    return stm_rows


def build_ddl(stm_rows, project_name, layer="silver"):
    type_map = {
        "int64": "BIGINT",
        "int32": "INTEGER",
        "float64": "DOUBLE PRECISION",
        "float32": "REAL",
        "object": "VARCHAR(512)",
        "bool": "BOOLEAN",
        "datetime64[ns]": "TIMESTAMP",
    }

    col_key = "silver_column" if layer == "silver" else "gold_column"
    ddl_lines = []
    for row in stm_rows:
        col = row[col_key]
        dtype = row["source_dtype"]
        sql_type = type_map.get(dtype, "VARCHAR(512)")
        nullable = "NOT NULL" if row["is_key"] else "NULL"
        ddl_lines.append(f"    {col} {sql_type} {nullable}")

    # Add SCD Type 2 columns for Gold layer
    if layer == "gold":
        scd2_columns = [
            "    _valid_from TIMESTAMP NOT NULL",
            "    _valid_to TIMESTAMP",
            "    _is_current BOOLEAN NOT NULL DEFAULT TRUE",
            "    _change_hash VARCHAR(64)",
            "    _last_updated TIMESTAMP NOT NULL"
        ]
        ddl_lines.extend(scd2_columns)
    
    ddl = (
        f"CREATE TABLE {project_name}_{layer} (\n"
        + ",\n".join(ddl_lines)
        + "\n);"
    )
    return ddl


def run_stage2(args):
    _stage_start = time.time()
    project_name = args.project_name
    stage1 = gate_check(project_name)

    # Smart pattern recommendation — use Stage 1 data + purpose unless user explicitly forced one
    _explicit_pattern = args.architecture_pattern
    if not _explicit_pattern or _explicit_pattern.lower() in ("auto", "", "recommend"):
        rec = recommend_architecture(stage1)
        architecture_pattern = rec["recommended_pattern"]
        print(f"[Stage 2] Smart pattern selection: '{architecture_pattern}' (confidence: {rec['confidence']})")
        for reason in rec["reasons"]:
            print(f"  → {reason}")
    else:
        rec = {
            "recommended_pattern": _explicit_pattern,
            "confidence": "USER_DEFINED",
            "scores": {},
            "reasons": [f"Pattern explicitly set by user: {_explicit_pattern}"],
            "description": ARCHITECTURE_PATTERNS.get(_explicit_pattern, {}).get("description", ""),
            "best_for": ARCHITECTURE_PATTERNS.get(_explicit_pattern, {}).get("best_for", ""),
        }
        architecture_pattern = _explicit_pattern
        print(f"[Stage 2] Using user-specified pattern: '{architecture_pattern}'")
    pipeline_type = args.pipeline_type or "batch"
    cloud = args.cloud or "local"
    join_keys_raw = args.join_keys or ""
    scd_type = args.scd_type or "1"
    null_strategy = args.null_strategy or ""
    upstream_systems = args.upstream_systems or stage1["source"]
    downstream_consumers = args.downstream_consumers or "Not specified"

    join_keys = [k.strip() for k in join_keys_raw.split(",") if k.strip()]

    if architecture_pattern not in ARCHITECTURE_PATTERNS:
        print(
            f"❌ Unknown architecture pattern: {architecture_pattern}. "
            f"Choose from: {list(ARCHITECTURE_PATTERNS.keys())}",
            file=sys.stderr,
        )
        sys.exit(1)

    arch_info = ARCHITECTURE_PATTERNS[architecture_pattern]

    out_dir = os.path.join(ARTIFACTS_BASE, project_name, "stage2")
    os.makedirs(out_dir, exist_ok=True)

    print(f"[Stage 2] Building STM from {len(stage1['columns'])} real columns...")
    stm_rows = build_stm(stage1, scd_type, join_keys, null_strategy)

    print("[Stage 2] Generating DDL for Silver and Gold layers...")
    ddl_silver = build_ddl(stm_rows, project_name, "silver")
    ddl_gold = build_ddl(stm_rows, project_name, "gold")

    stm_path = os.path.join(out_dir, "stm.csv")
    with open(stm_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(stm_rows[0].keys()))
        writer.writeheader()
        writer.writerows(stm_rows)

    pii_cols = [r["source_column"] for r in stm_rows if r["is_pii"]]

    architecture_doc = {
        "architecture_pattern": architecture_pattern,
        "pipeline_type": pipeline_type,
        "cloud": cloud,
        "layers": arch_info["layers"],
        "layer_description": arch_info["description"],
        "upstream_systems": upstream_systems,
        "downstream_consumers": downstream_consumers,
        "scd_type": scd_type,
        "join_keys": join_keys,
        "pii_columns_to_mask": pii_cols,
        "pipeline_schedule": "0 6 * * *",
        "load_strategy": "full",
    }

    arch_path = os.path.join(out_dir, "architecture_doc.json")
    with open(arch_path, "w") as f:
        json.dump(architecture_doc, f, indent=2)

    ddl_path = os.path.join(out_dir, "ddl.sql")
    with open(ddl_path, "w") as f:
        f.write("-- Silver Layer DDL\n")
        f.write(ddl_silver)
        f.write("\n\n-- Gold Layer DDL\n")
        f.write(ddl_gold)

    layer_definitions = {
        layer: {
            "name": layer,
            "purpose": {
                "bronze": "Raw data as-is from source — no transformations",
                "silver": "Cleaned, conformed, PII-masked, null-handled data",
                "gold": "Business-aggregated, analytics-ready data",
                "raw": "Raw ingested data",
                "transformed": "Cleaned and transformed output",
                "stream": "Real-time streaming events",
                "serving": "Low-latency serving layer",
                "speed": "Real-time speed layer",
            }.get(layer, layer),
        }
        for layer in arch_info["layers"]
    }

    # Detect load strategy from Stage 1
    load_strategy = stage1.get("load_type", "full")
    timestamp_column = stage1.get("timestamp_column", None)
    
    output = {
        "project_name": project_name,
        "architecture_pattern": architecture_pattern,
        "architecture_recommendation": rec,
        "pipeline_type": pipeline_type,
        "cloud": cloud,
        "load_strategy": load_strategy,
        "timestamp_column": timestamp_column,
        "layer_definitions": layer_definitions,
        "stm": stm_rows,
        "target_schema": {r["silver_column"]: r["source_dtype"] for r in stm_rows},
        "ddl_silver": ddl_silver,
        "ddl_gold": ddl_gold,
        "join_keys": join_keys,
        "scd_type": scd_type,
        "pii_columns_to_mask": pii_cols,
        "upstream_systems": upstream_systems,
        "downstream_consumers": downstream_consumers,
        "columns_mapped": len(stm_rows),
        "duration_seconds": round(time.time() - _stage_start, 2),
        "status": "COMPLETE",
    }

    out_path = os.path.join(out_dir, "stage2_output.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print("\n✅ Stage 2 Complete")
    print(f"   Architecture: {architecture_pattern} | Columns mapped: {len(stm_rows)}")
    print(f"   PII to mask: {pii_cols or 'None'}")
    print(f"   SCD type: {scd_type} | Join keys: {join_keys or 'None'}")
    print(f"   Output: {out_path}")
    print(json.dumps(output, indent=2, default=str))
    return output


def main():
    parser = argparse.ArgumentParser(description="DE Stage 2 — Solution Design & Architecture")
    parser.add_argument("--project_name", required=True)
    parser.add_argument("--architecture_pattern", default="auto",
                        help="auto (smart selection) / medallion / simple / lambda / kappa")
    parser.add_argument("--pipeline_type", default="batch",
                        help="batch / streaming / incremental / full_load")
    parser.add_argument("--cloud", default="local",
                        help="AWS / Azure / GCP / local / hybrid")
    parser.add_argument("--join_keys", default="",
                        help="Comma-separated join/dedup key columns")
    parser.add_argument("--scd_type", default="1",
                        help="SCD type: 1 (overwrite) / 2 (full history) / none")
    parser.add_argument("--null_strategy", default="",
                        help="Global null strategy override (drop / fill_zero / fill_unknown / flag)")
    parser.add_argument("--upstream_systems", default="",
                        help="Upstream system description")
    parser.add_argument("--downstream_consumers", default="",
                        help="Downstream consumers description")
    args = parser.parse_args()
    run_stage2(args)


if __name__ == "__main__":
    main()
