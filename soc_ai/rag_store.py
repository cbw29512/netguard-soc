#!/usr/bin/env python3
import sqlite3, json, time
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

def _connect(db_path: str) -> sqlite3.Connection:
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.execute("PRAGMA temp_store=MEMORY;")
    return con

def init_db(db_path: str) -> None:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    con = _connect(db_path)
    cur = con.cursor()

    # docs store + FTS index
    cur.execute("""
    CREATE TABLE IF NOT EXISTS docs (
      doc_id TEXT PRIMARY KEY,
      source TEXT,
      title TEXT,
      body TEXT,
      created_at INTEGER
    );
    """)
    cur.execute("""
    CREATE VIRTUAL TABLE IF NOT EXISTS docs_fts USING fts5(
      doc_id, title, body,
      content='docs', content_rowid='rowid',
      tokenize='porter'
    );
    """)
    cur.execute("""
    CREATE TRIGGER IF NOT EXISTS docs_ai AFTER INSERT ON docs BEGIN
      INSERT INTO docs_fts(rowid, doc_id, title, body)
      VALUES (new.rowid, new.doc_id, new.title, new.body);
    END;
    """)
    cur.execute("""
    CREATE TRIGGER IF NOT EXISTS docs_ad AFTER DELETE ON docs BEGIN
      INSERT INTO docs_fts(docs_fts, rowid, doc_id, title, body)
      VALUES('delete', old.rowid, old.doc_id, old.title, old.body);
    END;
    """)
    cur.execute("""
    CREATE TRIGGER IF NOT EXISTS docs_au AFTER UPDATE ON docs BEGIN
      INSERT INTO docs_fts(docs_fts, rowid, doc_id, title, body)
      VALUES('delete', old.rowid, old.doc_id, old.title, old.body);
      INSERT INTO docs_fts(rowid, doc_id, title, body)
      VALUES (new.rowid, new.doc_id, new.title, new.body);
    END;
    """)

    # numeric metrics for trends
    cur.execute("""
    CREATE TABLE IF NOT EXISTS metrics (
      ts INTEGER NOT NULL,
      name TEXT NOT NULL,
      value REAL NOT NULL,
      labels_json TEXT DEFAULT '{}'
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_metrics_name_ts ON metrics(name, ts);")

    # AI outputs for history
    cur.execute("""
    CREATE TABLE IF NOT EXISTS ai_insights (
      ts INTEGER NOT NULL,
      level TEXT NOT NULL,
      thought TEXT NOT NULL,
      context_json TEXT DEFAULT '{}'
    );
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_ai_insights_ts ON ai_insights(ts);")

    con.commit()
    con.close()

def upsert_doc(db_path: str, doc_id: str, source: str, title: str, body: str, created_at: Optional[int]=None) -> None:
    created_at = created_at or int(time.time())
    con = _connect(db_path)
    con.execute("""
      INSERT INTO docs(doc_id, source, title, body, created_at)
      VALUES(?,?,?,?,?)
      ON CONFLICT(doc_id) DO UPDATE SET
        source=excluded.source,
        title=excluded.title,
        body=excluded.body,
        created_at=excluded.created_at
    """, (doc_id, source, title, body, created_at))
    con.commit()
    con.close()

def add_metric(db_path: str, name: str, value: float, labels: Optional[Dict[str, Any]]=None, ts: Optional[int]=None) -> None:
    ts = ts or int(time.time())
    labels = labels or {}
    con = _connect(db_path)
    con.execute("INSERT INTO metrics(ts, name, value, labels_json) VALUES(?,?,?,?)",
                (ts, name, float(value), json.dumps(labels, separators=(",",":"))))
    con.commit()
    con.close()

def search_docs(db_path: str, query: str, limit: int=5) -> List[Dict[str, Any]]:
    con = _connect(db_path)
    cur = con.cursor()
    # bm25 gives smaller=better; we invert as a rough score
    cur.execute("""
      SELECT d.doc_id, d.source, d.title, d.body, d.created_at, bm25(docs_fts) AS rank
      FROM docs_fts
      JOIN docs d ON d.doc_id = docs_fts.doc_id
      WHERE docs_fts MATCH ?
      ORDER BY rank
      LIMIT ?;
    """, (query, limit))
    rows = cur.fetchall()
    con.close()
    out = []
    for doc_id, source, title, body, created_at, rank in rows:
        out.append({
            "doc_id": doc_id,
            "source": source,
            "title": title,
            "body": body,
            "created_at": created_at,
            "rank": rank,
        })
    return out

def metric_series(db_path: str, name: str, since_ts: int) -> List[Tuple[int, float]]:
    con = _connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT ts, value FROM metrics WHERE name=? AND ts>=? ORDER BY ts ASC", (name, since_ts))
    rows = cur.fetchall()
    con.close()
    return [(int(ts), float(val)) for ts, val in rows]

def record_ai(db_path: str, level: str, thought: str, context: Optional[Dict[str, Any]]=None, ts: Optional[int]=None) -> None:
    ts = ts or int(time.time())
    context = context or {}
    con = _connect(db_path)
    con.execute("INSERT INTO ai_insights(ts, level, thought, context_json) VALUES(?,?,?,?)",
                (ts, level, thought, json.dumps(context, separators=(",",":"))))
    con.commit()
    con.close()

def prune(db_path: str, keep_days: int=14) -> None:
    cutoff = int(time.time()) - keep_days*86400
    con = _connect(db_path)
    con.execute("DELETE FROM docs WHERE created_at < ?", (cutoff,))
    con.execute("DELETE FROM metrics WHERE ts < ?", (cutoff,))
    con.execute("DELETE FROM ai_insights WHERE ts < ?", (cutoff,))
    con.commit()
    con.close()
