"""
Stage 1 — Business & Data Understanding
Connects to the actual data source, profiles it completely, and captures the business purpose.
NO BRD. NO FRD. Data-first. Zero hallucination — all stats from real data only.
"""
import argparse
import json
import os
import sys
import re
import time

import pandas as pd

ARTIFACTS_BASE = os.environ.get("DE_ARTIFACTS_BASE", "/home/node/Music/de-artifacts")

PII_KEYWORDS = [
    "email", "phone", "mobile", "name", "dob", "birth", "address",
    "zip", "pincode", "ssn", "passport", "pan", "aadhar", "aadhaar",
    "credit_card", "card_number", "account_no", "account_number",
    "ip_address", "ip_addr", "gender", "nationality",
]

SUPPORTED_SOURCES = [
    "csv", "excel", "postgresql", "mysql", "sqlite",
    "snowflake", "s3", "bigquery", "rest_api", "oracle",
    "sqlserver", "kafka",
]


def sanitize_name(name):
    name = name.lower().strip()
    name = re.sub(r"[^a-z0-9_]", "_", name)
    name = re.sub(r"_+", "_", name).strip("_")
    return name[:50]


def detect_source_type(source_str):
    s = source_str.lower().strip()
    if s.startswith("postgresql://") or s.startswith("postgres://"):
        return "postgresql"
    if s.startswith("mysql"):
        return "mysql"
    if s.startswith("mssql") or s.startswith("sqlserver"):
        return "sqlserver"
    if s.startswith("oracle"):
        return "oracle"
    if s.startswith("s3://"):
        return "s3"
    if s.endswith(".csv"):
        return "csv"
    if s.endswith(".xlsx") or s.endswith(".xls"):
        return "excel"
    if s.endswith(".db") or s.endswith(".sqlite") or s.endswith(".sqlite3"):
        return "sqlite"
    if s.startswith("http") and "bigquery" in s:
        return "bigquery"
    if s.startswith("http"):
        return "rest_api"
    return "unknown"


def detect_pii_columns(columns):
    pii = []
    for col in columns:
        col_lower = col.lower()
        for keyword in PII_KEYWORDS:
            if keyword in col_lower:
                pii.append(col)
                break
    return pii


def read_csv(source, sample_rows=500):
    df_full = pd.read_csv(source, low_memory=False)
    sample = df_full.head(sample_rows)
    return df_full, sample


def read_excel(source, sample_rows=500):
    df_full = pd.read_excel(source)
    sample = df_full.head(sample_rows)
    return df_full, sample


def read_sqlite(source, table_or_query, sample_rows=500):
    import sqlite3
    conn = sqlite3.connect(source)
    if table_or_query.strip().lower().startswith("select"):
        df_full = pd.read_sql_query(table_or_query, conn)
    else:
        df_full = pd.read_sql_query(f"SELECT * FROM {table_or_query}", conn)
    conn.close()
    sample = df_full.head(sample_rows)
    return df_full, sample


def read_sqlalchemy(conn_str, table_or_query, sample_rows=500):
    from sqlalchemy import create_engine, text
    engine = create_engine(conn_str)
    if table_or_query.strip().lower().startswith("select"):
        query = table_or_query
    else:
        query = f"SELECT * FROM {table_or_query}"
    with engine.connect() as conn:
        df_full = pd.read_sql(text(query), conn)
    sample = df_full.head(sample_rows)
    return df_full, sample


def read_snowflake(account, user, password, warehouse, database, schema, table_or_query, sample_rows=500):
    import snowflake.connector
    ctx = snowflake.connector.connect(
        user=user,
        password=password,
        account=account,
        warehouse=warehouse,
        database=database,
        schema=schema,
    )
    cur = ctx.cursor()
    if table_or_query.strip().lower().startswith("select"):
        query = table_or_query
    else:
        query = f"SELECT * FROM {table_or_query}"
    cur.execute(query)
    df_full = cur.fetch_pandas_all()
    ctx.close()
    sample = df_full.head(sample_rows)
    return df_full, sample


def read_s3(s3_path, aws_access_key=None, aws_secret_key=None, sample_rows=500):
    import boto3
    from io import BytesIO
    s3_path = s3_path.replace("s3://", "")
    bucket, key = s3_path.split("/", 1)
    kwargs = {}
    if aws_access_key and aws_secret_key:
        kwargs = {
            "aws_access_key_id": aws_access_key,
            "aws_secret_access_key": aws_secret_key,
        }
    s3 = boto3.client("s3", **kwargs)
    obj = s3.get_object(Bucket=bucket, Key=key)
    body = obj["Body"].read()
    df_full = pd.read_csv(BytesIO(body))
    sample = df_full.head(sample_rows)
    return df_full, sample


def read_rest_api(url, auth_header=None, sample_rows=500):
    import requests
    headers = {}
    if auth_header:
        headers["Authorization"] = auth_header
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    if isinstance(data, list):
        df_full = pd.DataFrame(data)
    elif isinstance(data, dict):
        for key in data:
            if isinstance(data[key], list):
                df_full = pd.DataFrame(data[key])
                break
        else:
            df_full = pd.DataFrame([data])
    else:
        raise ValueError(f"Unexpected API response type: {type(data)}")
    sample = df_full.head(sample_rows)
    return df_full, sample


def profile_dataframe(df, project_name, out_dir):
    total_rows = len(df)
    columns = list(df.columns)
    num_cols = len(columns)

    schema = {}
    null_summary = {}
    for col in columns:
        dtype = str(df[col].dtype)
        null_count = int(df[col].isnull().sum())
        null_pct = round(null_count / total_rows * 100, 2) if total_rows > 0 else 0.0
        cardinality = int(df[col].nunique())
        schema[col] = {
            "dtype": dtype,
            "null_count": null_count,
            "null_pct": null_pct,
            "cardinality": cardinality,
        }
        if null_pct > 0:
            null_summary[col] = null_pct

    dup_count = int(df.duplicated().sum())
    dup_pct = round(dup_count / total_rows * 100, 2) if total_rows > 0 else 0.0

    pii_columns = detect_pii_columns(columns)

    date_columns = [
        col for col in columns
        if any(kw in col.lower() for kw in ["date", "time", "created", "updated", "timestamp", "at"])
    ]

    top_null_cols = sorted(null_summary.items(), key=lambda x: x[1], reverse=True)[:5]
    top_null_str = ", ".join([f"{c} ({p}%)" for c, p in top_null_cols]) if top_null_cols else "None"

    return {
        "total_rows": total_rows,
        "num_columns": num_cols,
        "columns": columns,
        "schema": schema,
        "null_summary": null_summary,
        "top_null_columns": top_null_str,
        "duplicate_count": dup_count,
        "duplicate_pct": dup_pct,
        "pii_columns": pii_columns,
        "date_columns": date_columns,
    }


def save_sample(df, project_name, out_dir, n=500):
    sample_path = os.path.join(out_dir, f"{project_name}_raw_sample.csv")
    df.head(n).to_csv(sample_path, index=False)
    return sample_path


def run_stage1(args):
    _stage_start = time.time()
    project_name = sanitize_name(args.project_name)
    source = args.source
    table_or_query = args.table or ""
    purpose = args.purpose or "Not specified"
    key_columns = args.key_columns or ""
    source_type = detect_source_type(source)

    out_dir = os.path.join(ARTIFACTS_BASE, project_name, "stage1")
    os.makedirs(out_dir, exist_ok=True)

    print(f"[Stage 1] Connecting to source: {source_type} → {source[:60]}...")

    try:
        if source_type == "csv":
            df, sample = read_csv(source)
        elif source_type == "excel":
            df, sample = read_excel(source)
        elif source_type == "sqlite":
            df, sample = read_sqlite(source, table_or_query or "SELECT * FROM main_table LIMIT 10000")
        elif source_type in ("postgresql", "mysql", "sqlserver", "oracle"):
            if not table_or_query:
                raise ValueError("Table or query is required for database sources. Use --table.")
            df, sample = read_sqlalchemy(source, table_or_query)
        elif source_type == "snowflake":
            sf_params = json.loads(args.snowflake_params or "{}")
            if not sf_params:
                raise ValueError("Snowflake params required. Use --snowflake_params as JSON string.")
            df, sample = read_snowflake(
                account=sf_params["account"],
                user=sf_params["user"],
                password=sf_params["password"],
                warehouse=sf_params["warehouse"],
                database=sf_params["database"],
                schema=sf_params["schema"],
                table_or_query=table_or_query or sf_params.get("table", ""),
            )
        elif source_type == "s3":
            df, sample = read_s3(
                source,
                aws_access_key=args.aws_access_key,
                aws_secret_key=args.aws_secret_key,
            )
        elif source_type == "rest_api":
            df, sample = read_rest_api(source, auth_header=args.api_auth_header)
        elif source_type == "kafka":
            print("[Stage 1] Kafka source detected. Architecture only — live consumption needs custom implementation.")
            output = {
                "project_name": project_name,
                "source": source,
                "source_type": "kafka",
                "purpose": purpose,
                "key_columns": key_columns,
                "total_rows": "UNKNOWN — Kafka streaming source",
                "num_columns": "UNKNOWN",
                "columns": [],
                "schema": {},
                "null_summary": {},
                "top_null_columns": "N/A",
                "duplicate_count": "N/A",
                "duplicate_pct": "N/A",
                "pii_columns": [],
                "date_columns": [],
                "sample_path": None,
                "status": "KAFKA_STUB",
                "note": "Kafka live ingestion not profiled. Proceed to Stage 2 for architecture design.",
            }
            out_path = os.path.join(out_dir, "stage1_output.json")
            with open(out_path, "w") as f:
                json.dump(output, f, indent=2)
            print(json.dumps(output, indent=2))
            return output
        else:
            raise ValueError(
                f"Unrecognized source type: '{source}'. "
                "Please provide a valid file path, connection string, or URL."
            )
    except Exception as e:
        error_msg = str(e)
        print(f"\n❌ Stage 1 FAILED — Could not connect to source.\nError: {error_msg}", file=sys.stderr)
        print("\nPlease check:", file=sys.stderr)
        print("  • The file path or connection string is correct", file=sys.stderr)
        print("  • The source is accessible from this machine", file=sys.stderr)
        print("  • Credentials are valid (if applicable)", file=sys.stderr)
        sys.exit(1)

    print(f"[Stage 1] Connected. Profiling {len(df):,} rows...")
    
    # NEW: Incremental load logic
    timestamp_col = detect_timestamp_column(df)
    load_type = "full"
    csv_prompt_sent = False
    
    # If CSV + prompt enabled + scheduled mode → send WhatsApp prompt and exit
    if source_type == "csv" and args.csv_prompt_enabled and args.start_date and args.end_date:
        sent = send_csv_upload_prompt(project_name, args.start_date, args.end_date, args.csv_prompt_user or None)
        if sent:
            csv_prompt_sent = True
            # Save minimal output and exit - pipeline will resume after upload
            output = {
                "project_name": project_name,
                "source": source,
                "source_type": source_type,
                "timestamp_column": timestamp_col,
                "start_date": args.start_date,
                "end_date": args.end_date,
                "load_type": "incremental",
                "csv_prompt_sent": True,
                "status": "AWAITING_CSV_UPLOAD",
                "note": "CSV upload prompt sent. Pipeline will resume after file is uploaded."
            }
            out_path = os.path.join(out_dir, "stage1_output.json")
            with open(out_path, "w") as f:
                json.dump(output, f, indent=2)
            print("\n⏸️  Stage 1 Paused - Awaiting CSV upload")
            print(f"   WhatsApp prompt sent. Upload file to continue.")
            print(f"   Output: {out_path}")
            return output
    
    # Apply date filter if start/end dates provided
    if args.start_date and args.end_date:
        df = apply_date_filter(df, timestamp_col, args.start_date, args.end_date)
        sample = df.head(500)  # Re-sample after filtering
        load_type = "incremental"
    
    profile = profile_dataframe(df, project_name, out_dir)
    sample_path = save_sample(sample, project_name, out_dir)

    output = {
        "project_name": project_name,
        "source": source,
        "source_type": source_type,
        "table_or_query": table_or_query,
        "purpose": purpose,
        "key_columns": [c.strip() for c in key_columns.split(",") if c.strip()] if key_columns else [],
        **profile,
        "sample_path": sample_path,
        "timestamp_column": timestamp_col,
        "start_date": args.start_date or None,
        "end_date": args.end_date or None,
        "load_type": load_type,
        "schedule_time": args.schedule_time or None,
        "csv_prompt_sent": csv_prompt_sent,
        "duration_seconds": round(time.time() - _stage_start, 2),
        "status": "COMPLETE",
    }

    out_path = os.path.join(out_dir, "stage1_output.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print("\n✅ Stage 1 Complete")
    print(f"   Rows: {output['total_rows']:,} | Columns: {output['num_columns']}")
    print(f"   PII detected: {output['pii_columns'] or 'None'}")
    print(f"   Nulls: {output['top_null_columns']}")
    print(f"   Duplicates: {output['duplicate_count']} ({output['duplicate_pct']}%)")
    print(f"   Output: {out_path}")
    print(json.dumps(output, indent=2))
    return output


def detect_timestamp_column(df):
    """Auto-detect the timestamp/date column in the dataframe."""
    timestamp_names = ['timestamp', 'created_at', 'updated_at', 'date', 'datetime',
                       'event_time', 'event_timestamp', 'time', 'dt', 'record_date']
    
    for col in df.columns:
        if col.lower() in timestamp_names:
            return col
    
    for col in df.columns:
        if pd.api.types.is_datetime64_any_dtype(df[col]):
            return col
    
    for col in df.columns:
        if df[col].dtype == 'object':
            try:
                sample = df[col].dropna().head(100)
                parsed = pd.to_datetime(sample, errors='coerce')
                if parsed.notna().sum() / len(sample) > 0.8:
                    return col
            except:
                continue
    
    return None


def apply_date_filter(df, timestamp_col, start_date, end_date):
    """Filter dataframe by date range."""
    if timestamp_col is None:
        print(f"⚠️  No timestamp column detected - cannot filter by date. Loading all data.", file=sys.stderr)
        return df
    
    if timestamp_col not in df.columns:
        print(f"⚠️  Timestamp column '{timestamp_col}' not found - loading all data.", file=sys.stderr)
        return df
    
    # Always convert timestamp column to datetime first
    df_filtered = df.copy()
    df_filtered[timestamp_col] = pd.to_datetime(df_filtered[timestamp_col], errors='coerce')
    
    start = pd.to_datetime(start_date) if start_date else None
    end = pd.to_datetime(end_date) if end_date else None
    
    if start:
        df_filtered = df_filtered[df_filtered[timestamp_col] >= start]
    if end:
        df_filtered = df_filtered[df_filtered[timestamp_col] < end]
    
    print(f"[Stage 1] Date filter applied: {start} → {end}")
    print(f"[Stage 1] Rows after filter: {len(df_filtered):,} (from {len(df):,})")
    
    return df_filtered


def send_csv_upload_prompt(project_name, start_date, end_date, user_number=None):
    """Send WhatsApp prompt to user to upload CSV file."""
    import subprocess
    
    start_display = pd.to_datetime(start_date).strftime("%Y-%m-%d %I:%M %p")
    end_display = pd.to_datetime(end_date).strftime("%Y-%m-%d %I:%M %p")
    
    message = f"""⏰ Daily Pipeline Ready - {project_name}

Upload CSV for:
📅 {start_display} → {end_display}

Reply with the file when ready."""
    
    if not user_number:
        user_number = "+918328286804"
    
    cmd = [
        "openclaw", "message", "send",
        "--channel", "whatsapp",
        "--target", user_number,
        "--message", message
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"✅ CSV upload prompt sent to {user_number}")
            return True
        else:
            print(f"⚠️  Failed to send WhatsApp prompt: {result.stderr}", file=sys.stderr)
            return False
    except Exception as e:
        print(f"⚠️  Failed to send WhatsApp prompt: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="DE Stage 1 - Business & Data Understanding")
    parser.add_argument("--project_name", required=True, help="Project name (sanitized automatically)")
    parser.add_argument("--source", required=True, help="Source: file path / connection string / URL")
    parser.add_argument("--table", default="", help="Table name or SQL query (for DB sources)")
    parser.add_argument("--purpose", default="", help="Business purpose of this data")
    parser.add_argument("--key_columns", default="", help="Key columns to focus on (comma-separated)")
    parser.add_argument("--snowflake_params", default="", help="Snowflake params as JSON string")
    parser.add_argument("--aws_access_key", default="", help="AWS access key for S3")
    parser.add_argument("--aws_secret_key", default="", help="AWS secret key for S3")
    parser.add_argument("--api_auth_header", default="", help="Auth header for REST API (e.g. 'Bearer token')")
    # NEW: Incremental load parameters
    parser.add_argument("--start_date", default="", help="Start of date window (ISO format: 2026-04-07T06:01:00)")
    parser.add_argument("--end_date", default="", help="End of date window (ISO format: 2026-04-08T06:00:00)")
    parser.add_argument("--schedule_time", default="", help="Daily pipeline schedule time (HH:MM, e.g., 06:00)")
    parser.add_argument("--csv_prompt_user", default="", help="WhatsApp number for CSV upload prompts")
    parser.add_argument("--csv_prompt_enabled", action="store_true", help="Enable WhatsApp CSV upload prompts")
    args = parser.parse_args()
    run_stage1(args)


if __name__ == "__main__":
    main()
