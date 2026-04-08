# Sales DB Pipeline - Incremental ETL

Automated database-to-database ETL pipeline with 10-minute incremental updates.

## Architecture

```
Source DB (sales_source.db)  →  Pipeline  →  Target DB (sales_target.db)
       115 rows              →  ETL + DQ   →  Silver + Gold (115 rows)
```

## How It Works

1. **Every 10 minutes**: GitHub Actions checks for new records
2. **If new data found**: Runs incremental pipeline (Stage 1 → Stage 2 → Stage 3)
3. **Appends to target DB**: Only processes new records, not full reload
4. **Commits results**: Updates `data/` folder with new target DB state

## Manual Trigger

Go to: [Actions](../../actions) → "Incremental Pipeline" → "Run workflow"

## Add Test Data

```bash
# Add 5 new records to source DB
python3 << 'PYTHON'
import sqlite3
from datetime import datetime
import random

db = 'data/sales_source.db'
conn = sqlite3.connect(db)
cur = conn.cursor()

now = datetime.now()
for i in range(5):
    cur.execute('''INSERT INTO sales_transactions 
    (transaction_date, customer_email, customer_phone, product_name, 
     quantity, unit_price, total_amount, status, region, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
    (now.strftime('%Y-%m-%d'), f'test{i}@new.com', f'+1-555-{8000+i}',
     'Monitor', 1, 299.99, 299.99, 'completed', 'West', 
     now.strftime('%Y-%m-%d %H:%M:%S')))

conn.commit()
print(f"✅ Added 5 records at {now}")
conn.close()
PYTHON

# Commit and push
git add data/sales_source.db
git commit -m "test: add 5 new transactions"
git push
```

## Monitor

**GitHub Actions Dashboard:**  
https://github.com/mudigitalemployee-tech/sales-db-pipeline-de-pipeline/actions

**Check target DB:**
```bash
python3 << 'PYTHON'
import sqlite3
conn = sqlite3.connect('data/sales_target.db')
cur = conn.cursor()
cur.execute("SELECT COUNT(*) FROM sales_clean")
print(f"Silver rows: {cur.fetchone()[0]}")
cur.execute("SELECT COUNT(*) FROM sales_analytics")
print(f"Gold rows: {cur.fetchone()[0]}")
conn.close()
PYTHON
```

## Status

- ✅ Initial load: 105 records
- ✅ Incremental test: +10 records
- ✅ Target DB: 115 rows total
- ✅ DQ Score: 100% (incremental data)
- ✅ PII masked: SHA256
- ✅ GitHub Actions: Scheduled every 10 min

**Next scheduled run:** Check [Actions](../../actions) page
