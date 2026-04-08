"""
Stage 3 — Engineering & Build
Reads Stage 1 (real schema) + Stage 2 (STM + architecture) and generates:
- transform.py (ETL code with real column names)
- Runs Bronze ingestion → Silver transforms → Gold aggregation
- DQ checks on Silver output
- PII masking (SHA256)
- dq_checks.py (crash-safe, flake8-clean)
GATE: stage2_output.json must exist and be complete.
"""
import argparse
import hashlib
import json
import os
import sys
import time

import pandas as pd

ARTIFACTS_BASE = os.environ.get("DE_ARTIFACTS_BASE", "/home/node/Music/de-artifacts")

REQUIRED_STAGE2_FIELDS = [
    "architecture_pattern", "pipeline_type", "layer_definitions", "stm", "target_schema"
]


def gate_check(project_name):
    stage2_path = os.path.join(ARTIFACTS_BASE, project_name, "stage2", "stage2_output.json")
    if not os.path.exists(stage2_path):
        print(
            "\n❌ Stage 3 BLOCKED.\n"
            f"Stage 2 output not found at: {stage2_path}\n"
            "Please complete Stage 2 first.\n",
            file=sys.stderr,
        )
        sys.exit(1)
    with open(stage2_path) as f:
        stage2 = json.load(f)
    missing = [field for field in REQUIRED_STAGE2_FIELDS if not stage2.get(field)]
    if missing:
        print(
            "\n❌ Stage 3 BLOCKED.\n"
            f"Stage 2 is incomplete. Missing: {missing}\n"
            "Please complete Stage 2 first.\n",
            file=sys.stderr,
        )
        sys.exit(1)
    return stage2


def load_stage1(project_name):
    path = os.path.join(ARTIFACTS_BASE, project_name, "stage1", "stage1_output.json")
    with open(path) as f:
        return json.load(f)


def _to_float(val):
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def sha256_col(series):
    return series.apply(
        lambda x: hashlib.sha256(str(x).encode()).hexdigest() if pd.notna(x) else x
    )


def read_source(stage1):
    """
    Read source data for Stage 3.
    For incremental loads, reads from Stage 1's filtered sample CSV.
    For full loads, re-queries the source.
    """
    source = stage1["source"]
    source_type = stage1["source_type"]
    table_or_query = stage1.get("table_or_query", "")
    load_type = stage1.get("load_type", "full")
    sample_path = stage1.get("sample_path")
    
    # For incremental loads, ALWAYS use Stage 1's filtered output (sample CSV)
    # This ensures we only process the records Stage 1 filtered by date
    if load_type == "incremental" and sample_path and os.path.exists(sample_path):
        print(f"[Stage 3] Incremental load - reading from Stage 1 filtered output: {sample_path}")
        return pd.read_csv(sample_path, low_memory=False)
    
    # For full loads, re-query the source
    if source_type == "csv":
        return pd.read_csv(source, low_memory=False)
    elif source_type == "excel":
        return pd.read_excel(source)
    elif source_type == "sqlite":
        import sqlite3
        conn = sqlite3.connect(source)
        query = table_or_query if table_or_query.lower().startswith("select") else f"SELECT * FROM {table_or_query}"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    elif source_type in ("postgresql", "mysql", "sqlserver", "oracle"):
        from sqlalchemy import create_engine, text
        engine = create_engine(source)
        query = table_or_query if table_or_query.lower().startswith("select") else f"SELECT * FROM {table_or_query}"
        with engine.connect() as conn:
            return pd.read_sql(text(query), conn)
    else:
        if sample_path and os.path.exists(sample_path):
            print(f"[Stage 3] Using sample CSV (source type '{source_type}' not directly supported for re-read)")
            return pd.read_csv(sample_path, low_memory=False)
        raise ValueError(
            f"Cannot re-read source type '{source_type}' automatically. "
            f"Ensure sample CSV exists at: {stage1.get('sample_path', 'N/A')}"
        )


def apply_transforms(df, stm_rows, custom_rules_str, null_fail_threshold, dup_fail_threshold):
    transform_log = []
    rows_in = len(df)
    df = df.copy()

    for row in stm_rows:
        col = row["source_column"]
        transform = row["silver_transform"]
        if col not in df.columns:
            continue
        if transform == "SHA256_hash":
            df[col] = sha256_col(df[col])
            transform_log.append({
                "step": f"pii_mask_{col}",
                "layer": "silver",
                "action": f"SHA256 hash applied to {col}",
                "rows_in": rows_in,
                "rows_out": len(df),
                "notes": f"PII column {col} hashed for privacy compliance",
            })
        elif transform.startswith("null_handle:"):
            strategy = transform.split(":")[1]
            if strategy == "drop":
                before = len(df)
                df = df[df[col].notna()]
                transform_log.append({
                    "step": f"null_drop_{col}",
                    "layer": "silver",
                    "action": f"Drop rows with null {col}",
                    "rows_in": before,
                    "rows_out": len(df),
                    "notes": f"Dropped {before - len(df)} rows where {col} was null",
                })
            elif strategy == "fill_zero":
                df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
                transform_log.append({
                    "step": f"null_fill_zero_{col}",
                    "layer": "silver",
                    "action": f"Fill nulls with 0 in {col}",
                    "rows_in": rows_in,
                    "rows_out": len(df),
                    "notes": f"Numeric nulls in {col} filled with 0",
                })
            elif strategy == "fill_mean":
                numeric_col = pd.to_numeric(df[col], errors="coerce")
                mean_val = numeric_col.mean()
                df[col] = numeric_col.fillna(mean_val if pd.notna(mean_val) else 0)
                transform_log.append({
                    "step": f"null_fill_mean_{col}",
                    "layer": "silver",
                    "action": f"Fill nulls with mean in {col}",
                    "rows_in": rows_in,
                    "rows_out": len(df),
                    "notes": "Null values in " + col + " filled with column mean",
                })
            elif strategy == "fill_unknown":
                df[col] = df[col].fillna("UNKNOWN")
                transform_log.append({
                    "step": f"null_fill_unknown_{col}",
                    "layer": "silver",
                    "action": f"Fill nulls with UNKNOWN in {col}",
                    "rows_in": rows_in,
                    "rows_out": len(df),
                    "notes": f"String nulls in {col} filled with UNKNOWN",
                })
            elif strategy == "flag":
                df[f"{col}_is_null"] = df[col].isnull().astype(int)
                transform_log.append({
                    "step": f"null_flag_{col}",
                    "layer": "silver",
                    "action": f"Add null flag for {col}",
                    "rows_in": rows_in,
                    "rows_out": len(df),
                    "notes": f"Added {col}_is_null indicator column",
                })
            elif strategy == "ffill_bfill_else_drop":
                # Key/ID column: forward-fill → backward-fill → drop only if still null
                before = len(df)
                null_before = int(df[col].isnull().sum())
                df[col] = df[col].ffill().bfill()
                null_after = int(df[col].isnull().sum())
                filled = null_before - null_after
                if null_after > 0:
                    df = df[df[col].notna()]
                dropped = before - len(df)
                action_parts = []
                if filled > 0:
                    action_parts.append(f"forward/backward filled {filled} null(s)")
                if dropped > 0:
                    action_parts.append(f"dropped {dropped} row(s) still null after fill")
                if not action_parts:
                    action_parts.append("no nulls found")
                transform_log.append({
                    "step": f"null_ffill_bfill_{col}",
                    "layer": "silver",
                    "action": f"Fill then drop nulls in key column {col}",
                    "rows_in": before,
                    "rows_out": len(df),
                    "notes": (
                        f"Key column '{col}': {'; '.join(action_parts)}. "
                        f"Rows dropped only when fill was not possible."
                    ),
                })

    if custom_rules_str:
        for rule in custom_rules_str.split(";"):
            rule = rule.strip()
            if not rule:
                continue
            if "=" in rule and "→" not in rule:
                parts = rule.split("=", 1)
                col_name = parts[0].strip()
                expr = parts[1].strip()
                try:
                    df[col_name] = df.eval(expr)
                    transform_log.append({
                        "step": f"custom_{col_name}",
                        "layer": "silver",
                        "action": f"Custom: {col_name} = {expr}",
                        "rows_in": len(df),
                        "rows_out": len(df),
                        "notes": f"Custom business rule applied: {rule}",
                    })
                except Exception as e:
                    print(f"[Stage 3] Warning: could not apply rule '{rule}': {e}")

    # Auto-clamp negative values in spend/budget/revenue columns — flag and set to 0
    _numeric_cols_to_clamp = [col for col in df.columns
                               if any(kw in col.lower() for kw in ["spend", "budget", "revenue", "amount", "cost", "price"])
                               and df[col].dtype in ("int64", "float64", "int32", "float32")]
    for col in _numeric_cols_to_clamp:
        neg_count = int((pd.to_numeric(df[col], errors="coerce") < 0).sum())
        if neg_count > 0:
            df[f"{col}_had_negative"] = (pd.to_numeric(df[col], errors="coerce") < 0).astype(int)
            df[col] = pd.to_numeric(df[col], errors="coerce").clip(lower=0)
            transform_log.append({
                "step": f"clamp_negative_{col}",
                "layer": "silver",
                "action": f"Clamp negative values in {col} to 0",
                "rows_in": len(df),
                "rows_out": len(df),
                "notes": f"{neg_count} negative value(s) in {col} set to 0. Original flagged in {col}_had_negative.",
            })

    df = df.drop_duplicates()
    silver_rows = len(df)
    transform_log.append({
        "step": "dedup_silver",
        "layer": "silver",
        "action": "Remove duplicate rows",
        "rows_in": rows_in,
        "rows_out": silver_rows,
        "notes": f"Removed {rows_in - silver_rows} duplicate rows in Silver layer",
    })

    return df, transform_log


def run_dq_checks(df, schema, null_threshold, dup_threshold, range_rules_str):
    checks = []
    total = len(df)

    for col in df.columns:
        null_count = int(df[col].isnull().sum())
        null_pct = round(null_count / total * 100, 2) if total > 0 else 0.0
        status = "PASS" if null_pct <= null_threshold else "FAIL"
        checks.append({
            "category": "Completeness",
            "column": col,
            "check": f"Null % ≤ {null_threshold}%",
            "value": null_pct,
            "threshold": null_threshold,
            "status": status,
        })

    dup_count = int(df.duplicated().sum())
    dup_pct = round(dup_count / total * 100, 2) if total > 0 else 0.0
    dup_status = "PASS" if dup_pct <= dup_threshold else "FAIL"
    checks.append({
        "category": "Uniqueness",
        "column": "_all_",
        "check": f"Duplicate % ≤ {dup_threshold}%",
        "value": dup_pct,
        "threshold": dup_threshold,
        "status": dup_status,
    })

    if range_rules_str:
        for rule in range_rules_str.split(","):
            rule = rule.strip()
            parts = rule.split(":")
            if len(parts) == 3:
                col, min_val, max_val = parts[0].strip(), parts[1].strip(), parts[2].strip()
                if col in df.columns:
                    numeric = pd.to_numeric(df[col], errors="coerce")
                    min_f = _to_float(min_val)
                    max_f = _to_float(max_val)
                    if min_f is not None:
                        violations = int((numeric < min_f).sum())
                        checks.append({
                            "category": "Range",
                            "column": col,
                            "check": f"{col} ≥ {min_f}",
                            "value": violations,
                            "threshold": 0,
                            "status": "PASS" if violations == 0 else "FAIL",
                        })
                    if max_f is not None:
                        violations = int((numeric > max_f).sum())
                        checks.append({
                            "category": "Range",
                            "column": col,
                            "check": f"{col} ≤ {max_f}",
                            "value": violations,
                            "threshold": 0,
                            "status": "PASS" if violations == 0 else "FAIL",
                        })

    passed = sum(1 for c in checks if c["status"] == "PASS")
    warnings = sum(1 for c in checks if c["status"] == "WARN")
    failed = sum(1 for c in checks if c["status"] == "FAIL")
    total_checks = len(checks)
    score = round(passed / total_checks * 100, 1) if total_checks > 0 else 100.0
    dq_status = "PASS" if failed == 0 else ("WARN" if warnings > 0 and failed == 0 else "FAIL")

    return {
        "dq_score_pct": score,
        "dq_status": dq_status,
        "passed": passed,
        "warnings": warnings,
        "failed": failed,
        "total_checks": total_checks,
        "checks": checks,
    }


def apply_scd2_merge(new_df, existing_gold_path, key_columns, tracked_columns):
    """
    Apply SCD Type 2 merge logic.
    Compares new_df vs existing Gold, tracks changes.
    
    Returns: merged dataframe with SCD Type 2 columns
    """
    import hashlib
    
    def compute_hash(row):
        """Compute MD5 hash of tracked columns."""
        values = "".join([str(row[col]) for col in tracked_columns if col in row.index])
        return hashlib.md5(values.encode()).hexdigest()
    
    now = pd.Timestamp.now()
    
    # First run - no existing Gold
    if not os.path.exists(existing_gold_path):
        print(f"[Stage 3] First run - all {len(new_df)} records are new")
        new_df['_valid_from'] = now
        new_df['_valid_to'] = None
        new_df['_is_current'] = True
        new_df['_change_hash'] = new_df.apply(compute_hash, axis=1)
        new_df['_last_updated'] = now
        return new_df, {"new": len(new_df), "changed": 0, "unchanged": 0, "expired": 0}
    
    # Load existing Gold
    existing = pd.read_csv(existing_gold_path)
    existing_current = existing[existing['_is_current'] == True].copy()
    
    if len(existing_current) == 0:
        print(f"[Stage 3] No current records in existing Gold - treating all as new")
        new_df['_valid_from'] = now
        new_df['_valid_to'] = None
        new_df['_is_current'] = True
        new_df['_change_hash'] = new_df.apply(compute_hash, axis=1)
        new_df['_last_updated'] = now
        return pd.concat([existing, new_df]), {"new": len(new_df), "changed": 0, "unchanged": 0, "expired": 0}
    
    # Compute hashes for new data
    new_df = new_df.copy()
    new_df['_change_hash'] = new_df.apply(compute_hash, axis=1)
    
    # Merge on key columns
    merged = new_df.merge(
        existing_current[key_columns + ['_change_hash']], 
        on=key_columns, 
        how='left', 
        suffixes=('_new', '_old'),
        indicator=True
    )
    
    # Classify records
    new_records = merged[merged['_merge'] == 'left_only'].copy()
    potential_changes = merged[merged['_merge'] == 'both'].copy()
    
    # Detect actual changes (hash mismatch)
    changed_records = potential_changes[potential_changes['_change_hash_new'] != potential_changes['_change_hash_old']].copy()
    unchanged_records = potential_changes[potential_changes['_change_hash_new'] == potential_changes['_change_hash_old']].copy()
    
    # Prepare new records
    new_final = new_df[new_df[key_columns[0]].isin(new_records[key_columns[0]])].copy()
    new_final['_valid_from'] = now
    new_final['_valid_to'] = None
    new_final['_is_current'] = True
    new_final['_last_updated'] = now
    
    # Expire old versions of changed records
    expired = existing_current[existing_current[key_columns[0]].isin(changed_records[key_columns[0]])].copy()
    expired['_valid_to'] = now
    expired['_is_current'] = False
    
    # Insert new versions of changed records
    changed_final = new_df[new_df[key_columns[0]].isin(changed_records[key_columns[0]])].copy()
    changed_final['_valid_from'] = now
    changed_final['_valid_to'] = None
    changed_final['_is_current'] = True
    changed_final['_last_updated'] = now
    
    # Combine: historical records + expired + unchanged current + new + changed_new
    historical = existing[existing['_is_current'] == False]
    unchanged_current = existing_current[existing_current[key_columns[0]].isin(unchanged_records[key_columns[0]])]
    
    final = pd.concat([historical, expired, unchanged_current, new_final, changed_final], ignore_index=True)
    
    stats = {
        "new": len(new_final),
        "changed": len(changed_final),
        "unchanged": len(unchanged_records),
        "expired": len(expired)
    }
    
    print(f"[Stage 3] SCD Type 2 merge: {stats['new']} new | {stats['changed']} changed | {stats['unchanged']} unchanged")
    
    return final, stats


def build_gold(df, agg_level):
    if not agg_level or agg_level.lower() in ("none", "no", ""):
        gold = df.copy()
        gold["_record_count"] = 1
        return gold, f"No aggregation — Gold = Silver ({len(gold)} rows)"

    numeric_cols = df.select_dtypes(include="number").columns.tolist()
    if not numeric_cols:
        gold = df.copy()
        gold["_record_count"] = 1
        return gold, "No numeric columns found for aggregation — Gold = Silver"

    agg_cols = [c.strip() for c in agg_level.split(",") if c.strip() in df.columns]
    if not agg_cols:
        gold = df.copy()
        gold["_record_count"] = 1
        return gold, f"Aggregation column(s) not found in schema: {agg_level} — Gold = Silver"

    agg_dict = {col: "sum" for col in numeric_cols if col not in agg_cols}
    agg_dict["_record_count"] = "count"
    df["_record_count"] = 1
    gold = df.groupby(agg_cols).agg(agg_dict).reset_index()
    return gold, f"Aggregated by {agg_cols} — {len(gold)} groups"


def write_to_database(df, db_path, table_name, if_exists='append'):
    """Write dataframe to SQLite database."""
    import sqlite3
    conn = sqlite3.connect(db_path)
    df.to_sql(table_name, conn, if_exists=if_exists, index=False)
    conn.close()
    print(f"[Stage 3] Written {len(df)} rows to {db_path} → {table_name}")
    return db_path


def run_stage3(args):
    _stage_start = time.time()
    project_name = args.project_name
    stage2 = gate_check(project_name)
    stage1 = load_stage1(project_name)

    null_threshold = float(args.null_threshold or 5.0)
    dup_threshold = float(args.dup_threshold or 1.0)
    agg_level = args.agg_level or ""
    custom_rules = args.custom_rules or ""
    range_rules = args.range_rules or ""
    dq_fail_action = args.dq_fail_action or "block"

    out_dir = os.path.join(ARTIFACTS_BASE, project_name, "stage3")
    os.makedirs(out_dir, exist_ok=True)

    print("[Stage 3] Reading source data...")
    try:
        df_raw = read_source(stage1)
    except Exception as e:
        print(f"\n❌ Stage 3 FAILED — Could not read source: {e}", file=sys.stderr)
        sys.exit(1)

    raw_rows = len(df_raw)
    print(f"[Stage 3] Bronze: {raw_rows:,} rows ingested.")

    # Partition Bronze by date if incremental load
    load_strategy = stage2.get("load_strategy", "full")
    if load_strategy == "incremental" and stage1.get("end_date"):
        # Use end_date to determine partition
        partition_date = pd.to_datetime(stage1["end_date"]).strftime("%Y-%m-%d")
        bronze_dir = os.path.join(out_dir, "bronze", partition_date)
        os.makedirs(bronze_dir, exist_ok=True)
        bronze_path = os.path.join(bronze_dir, f"{project_name}_bronze.csv")
        print(f"[Stage 3] Bronze partitioned by date: {partition_date}")
    else:
        bronze_path = os.path.join(out_dir, f"{project_name}_bronze.csv")
    
    df_raw.to_csv(bronze_path, index=False)

    print("[Stage 3] Applying Silver transforms...")
    stm_rows = stage2["stm"]
    df_silver, transform_log = apply_transforms(df_raw, stm_rows, custom_rules, null_threshold, dup_threshold)

    silver_path = os.path.join(out_dir, f"{project_name}_transformed.csv")
    df_silver.to_csv(silver_path, index=False)
    print(f"[Stage 3] Silver: {len(df_silver):,} rows after transforms.")

    print("[Stage 3] Running DQ checks on Silver layer...")
    dq_scorecard = run_dq_checks(df_silver, stage1["schema"], null_threshold, dup_threshold, range_rules)

    dq_path = os.path.join(out_dir, "dq_scorecard.json")
    with open(dq_path, "w") as f:
        json.dump(dq_scorecard, f, indent=2)

    if dq_scorecard["failed"] > 0 and dq_fail_action == "block":
        failed_checks = [c for c in dq_scorecard["checks"] if c["status"] == "FAIL"]
        failed_str = "\n".join(
            [f"  • {c['column']}: {c['check']} (value: {c['value']})" for c in failed_checks[:5]]
        )
        print(
            "\n❌ Stage 3 DQ GATE FAILED\n"
            f"DQ Score: {dq_scorecard['dq_score_pct']}% — {dq_scorecard['failed']} check(s) failed:\n"
            f"{failed_str}\n"
            "\nFix the data quality issues or rerun with --dq_fail_action warn to proceed.\n"
            "Stage 4 is BLOCKED until DQ passes.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[Stage 3] Building Gold layer (agg: {agg_level or 'none'})...")
    
    # Check if SCD Type 2 should be applied
    scd_type = stage2.get("scd_type", "1")
    load_strategy = stage2.get("load_strategy", "full")
    scd2_enabled = (scd_type == "2" and load_strategy == "incremental")
    
    if scd2_enabled:
        # SCD Type 2 merge logic
        key_columns = stage2.get("join_keys", []) or [df_silver.columns[0]]  # Use first column as key if none specified
        tracked_columns = [col for col in df_silver.columns if col not in key_columns]
        
        gold_path = os.path.join(out_dir, f"{project_name}_gold_aggregated.csv")
        df_gold, scd_stats = apply_scd2_merge(df_silver, gold_path, key_columns, tracked_columns)
        gold_note = f"SCD Type 2 applied: {scd_stats['new']} new | {scd_stats['changed']} changed | {scd_stats['unchanged']} unchanged"
    else:
        # Standard Gold build (aggregation or pass-through)
        df_gold, gold_note = build_gold(df_silver, agg_level)
    
    gold_path = os.path.join(out_dir, f"{project_name}_gold_aggregated.csv")
    df_gold.to_csv(gold_path, index=False)
    print(f"[Stage 3] Gold: {len(df_gold):,} rows. {gold_note}")

    # NEW: Write to database if output_db specified
    output_db_path = None
    if args.output_db:
        output_db_path = args.output_db
        silver_table = args.output_table_silver or f"{project_name}_silver"
        gold_table = args.output_table_gold or f"{project_name}_gold"
        write_mode = args.db_write_mode
        
        write_to_database(df_silver, output_db_path, silver_table, if_exists=write_mode)
        write_to_database(df_gold, output_db_path, gold_table, if_exists=write_mode)
        
        print(f"[Stage 3] Database output: {output_db_path}")
        print(f"[Stage 3]   Silver → {silver_table} ({len(df_silver)} rows)")
        print(f"[Stage 3]   Gold → {gold_table} ({len(df_gold)} rows)")

    pii_masked = [r["source_column"] for r in stm_rows if r.get("is_pii")]

    transform_log_path = os.path.join(out_dir, "transform_log.json")
    with open(transform_log_path, "w") as f:
        json.dump(transform_log, f, indent=2)

    output = {
        "project_name": project_name,
        "bronze_rows": raw_rows,
        "silver_rows": len(df_silver),
        "gold_rows": len(df_gold),
        "gold_note": gold_note,
        "transform_count": len(transform_log),
        "transform_log": transform_log,
        "silver_csv_path": silver_path,
        "gold_csv_path": gold_path,
        "output_db_path": output_db_path,
        "output_table_silver": args.output_table_silver or f"{project_name}_silver" if output_db_path else None,
        "output_table_gold": args.output_table_gold or f"{project_name}_gold" if output_db_path else None,
        "dq_scorecard": dq_scorecard,
        "pii_masked_columns": pii_masked,
        "dq_score_pct": dq_scorecard["dq_score_pct"],
        "dq_status": dq_scorecard["dq_status"],
        "duration_seconds": round(time.time() - _stage_start, 2),
        "status": "COMPLETE",
    }

    out_path = os.path.join(out_dir, "stage3_output.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print("\n✅ Stage 3 Complete")
    print(f"   Bronze: {raw_rows:,} → Silver: {len(df_silver):,} → Gold: {len(df_gold):,}")
    print(f"   DQ Score: {dq_scorecard['dq_score_pct']}% | PII masked: {pii_masked or 'None'}")
    print(f"   Output: {out_path}")
    return output


def main():
    parser = argparse.ArgumentParser(description="DE Stage 3 — Engineering & Build")
    parser.add_argument("--project_name", required=True)
    parser.add_argument("--null_threshold", default="5.0", help="Max null % per column before FAIL")
    parser.add_argument("--dup_threshold", default="1.0", help="Max duplicate % before FAIL")
    parser.add_argument("--agg_level", default="", help="Gold aggregation column(s), comma-separated")
    parser.add_argument("--custom_rules", default="", help="Custom business rules (semicolon-separated: col=expr)")
    parser.add_argument("--range_rules", default="", help="Range rules (comma-separated: col:min:max)")
    parser.add_argument("--dq_fail_action", default="block", help="block (default) or warn")
    # NEW: Database output parameters
    parser.add_argument("--output_db", default="", help="Target database path for clean data")
    parser.add_argument("--output_table_silver", default="", help="Target table name for Silver layer")
    parser.add_argument("--output_table_gold", default="", help="Target table name for Gold layer")
    parser.add_argument("--db_write_mode", default="replace", help="Database write mode: append or replace")
    args = parser.parse_args()
    run_stage3(args)


if __name__ == "__main__":
    main()
