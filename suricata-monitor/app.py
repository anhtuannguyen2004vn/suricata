#!/usr/bin/env python3
"""Defensive Suricata EVE JSON monitor with a small web dashboard."""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("MONITOR_DB", BASE_DIR / "data" / "alerts.sqlite3"))
EVE_PATH = Path(os.environ.get("SURICATA_EVE", "/var/log/suricata/eve.json"))
BIND = os.environ.get("MONITOR_BIND", "127.0.0.1")
PORT = int(os.environ.get("MONITOR_PORT", "8080"))
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "1"))
LOG = logging.getLogger("suricata_monitor")
MODEL_PATH = BASE_DIR / "models" / "suricata_iforest.joblib"
AI_MODEL = None
AI_STATUS = "Chưa nạp mô hình AI"

try:
    from ai_model import load_model, score_flow
except ImportError as exc:
    load_model = score_flow = None
    AI_STATUS = f"Thiếu thư viện AI: {exc}"


def db_connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_key TEXT UNIQUE NOT NULL,
            timestamp TEXT NOT NULL,
            signature TEXT NOT NULL,
            category TEXT DEFAULT '',
            severity INTEGER DEFAULT 3,
            src_ip TEXT DEFAULT '', src_port INTEGER,
            dest_ip TEXT DEFAULT '', dest_port INTEGER,
            protocol TEXT DEFAULT '', action TEXT DEFAULT '',
            source TEXT DEFAULT 'Suricata', anomaly_score REAL,
            raw_json TEXT NOT NULL
        )""")
        columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
        if "source" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN source TEXT DEFAULT 'Suricata'")
        if "anomaly_score" not in columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN anomaly_score REAL")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp DESC)")


def parse_alert(event: dict):
    if event.get("event_type") != "alert" or not isinstance(event.get("alert"), dict):
        return None
    alert = event["alert"]
    raw = json.dumps(event, ensure_ascii=False, sort_keys=True)
    flow = event.get("flow", {}) if isinstance(event.get("flow"), dict) else {}
    return {
        "event_key": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "timestamp": str(event.get("timestamp") or datetime.now(timezone.utc).isoformat()),
        "signature": str(alert.get("signature") or "(không có tên luật)"),
        "category": str(alert.get("category") or ""),
        "severity": int(alert.get("severity") or 3),
        "src_ip": str(event.get("src_ip") or ""),
        "src_port": event.get("src_port"),
        "dest_ip": str(event.get("dest_ip") or ""),
        "dest_port": event.get("dest_port"),
        "protocol": str(event.get("proto") or ""),
        "action": str(alert.get("action") or ""),
        "source": "Suricata",
        "anomaly_score": None,
        "raw_json": raw,
    }


def save_event(event: dict):
    row = parse_alert(event)
    if row is None:
        return False
    cols = ",".join(row.keys())
    marks = ",".join("?" for _ in row)
    with db_connect() as conn:
        cur = conn.execute(f"INSERT OR IGNORE INTO alerts ({cols}) VALUES ({marks})", tuple(row.values()))
        return cur.rowcount > 0


def save_ai_anomaly(event: dict, score: float):
    raw = json.dumps(event, ensure_ascii=False, sort_keys=True)
    flow = event.get("flow", {}) if isinstance(event.get("flow"), dict) else {}
    row = {
        "event_key": "ai:" + hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "timestamp": str(event.get("timestamp") or datetime.now(timezone.utc).isoformat()),
        "signature": "AI phát hiện luồng có đặc trưng bất thường",
        "category": "Phát hiện bất thường · cần kiểm tra thủ công",
        "severity": 2,
        "src_ip": str(event.get("src_ip") or ""),
        "src_port": event.get("src_port"),
        "dest_ip": str(event.get("dest_ip") or ""),
        "dest_port": event.get("dest_port"),
        "protocol": str(event.get("proto") or ""),
        "action": "AI anomaly",
        "source": "AI",
        "anomaly_score": round(score, 6),
        "raw_json": raw,
    }
    with db_connect() as conn:
        cols = ",".join(row.keys())
        marks = ",".join("?" for _ in row)
        cur = conn.execute(f"INSERT OR IGNORE INTO alerts ({cols}) VALUES ({marks})", tuple(row.values()))
        return cur.rowcount > 0


class EveTailer(threading.Thread):
    """Follow appended EVE JSON lines and reset safely after file rotation/truncation."""
    daemon = True

    def __init__(self, path: Path):
        super().__init__(name="eve-tailer")
        self.path = path
        self.stop_event = threading.Event()
        self.inode = None
        self.offset = 0
        self.partial = b""

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.read_new_data()
            except FileNotFoundError:
                pass
            except Exception:
                LOG.exception("Lỗi khi đọc EVE JSON")
            self.stop_event.wait(POLL_SECONDS)

    def read_new_data(self):
        stat = self.path.stat()
        if self.inode != stat.st_ino or stat.st_size < self.offset:
            self.inode, self.offset, self.partial = stat.st_ino, 0, b""
        with self.path.open("rb") as stream:
            stream.seek(self.offset)
            chunk = stream.read()
            self.offset = stream.tell()
        if not chunk:
            return
        lines = (self.partial + chunk).split(b"\n")
        self.partial = lines.pop()
        for line in lines:
            if not line.strip():
                continue
            try:
                event = json.loads(line.decode("utf-8"))
                if isinstance(event, dict):
                    if event.get("event_type") == "alert":
                        save_event(event)
                    elif event.get("event_type") == "flow" and AI_MODEL is not None and score_flow:
                        is_anomaly, score = score_flow(AI_MODEL, event)
                        if is_anomaly:
                            save_ai_anomaly(event, score)
            except (UnicodeDecodeError, json.JSONDecodeError):
                LOG.warning("Bỏ qua một dòng EVE JSON không hợp lệ")


def json_response(handler, payload, status=200):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        LOG.info("%s - %s", self.address_string(), fmt % args)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            try:
                body = (BASE_DIR / "templates" / "index.html").read_bytes()
            except OSError:
                return json_response(self, {"error": "Không tìm thấy giao diện"}, 500)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/api/stats":
            with db_connect() as conn:
                total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                ai_total = conn.execute("SELECT COUNT(*) FROM alerts WHERE source='AI'").fetchone()[0]
                critical = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity=1").fetchone()[0]
                high = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity=2").fetchone()[0]
                latest = conn.execute("SELECT MAX(timestamp) FROM alerts").fetchone()[0]
            json_response(self, {"total": total, "critical": critical, "high": high,
                                 "ai_total": ai_total, "ai_status": AI_STATUS,
                                 "latest": latest, "eve_path": str(EVE_PATH)})
        elif parsed.path == "/api/alerts":
            query = parse_qs(parsed.query)
            try:
                limit = max(1, min(int(query.get("limit", ["100"])[0]), 500))
            except ValueError:
                limit = 100
            search = query.get("q", [""])[0].strip()[:120]
            sev = query.get("severity", [""])[0]
            sql = "SELECT id,timestamp,signature,category,severity,src_ip,src_port,dest_ip,dest_port,protocol,action,source,anomaly_score,raw_json FROM alerts"
            clauses, params = [], []
            if search:
                clauses.append("(signature LIKE ? OR src_ip LIKE ? OR dest_ip LIKE ? OR category LIKE ?)")
                params.extend([f"%{search}%"] * 4)
            if sev in {"1", "2", "3", "4"}:
                clauses.append("severity=?")
                params.append(int(sev))
            if clauses:
                sql += " WHERE " + " AND ".join(clauses)
            sql += " ORDER BY timestamp DESC, id DESC LIMIT ?"
            params.append(limit)
            with db_connect() as conn:
                rows = [dict(row) for row in conn.execute(sql, params).fetchall()]
            for row in rows:
                try:
                    event = json.loads(row.pop("raw_json"))
                except (TypeError, json.JSONDecodeError):
                    event = {}
                flow = event.get("flow", {}) if isinstance(event.get("flow"), dict) else {}
                alert = event.get("alert", {}) if isinstance(event.get("alert"), dict) else {}
                row["flow_details"] = {
                    "bytes_toserver": flow.get("bytes_toserver", 0),
                    "bytes_toclient": flow.get("bytes_toclient", 0),
                    "pkts_toserver": flow.get("pkts_toserver", 0),
                    "pkts_toclient": flow.get("pkts_toclient", 0),
                    "duration_seconds": flow.get("age", 0),
                    "app_proto": event.get("app_proto", ""),
                    "state": flow.get("state", ""),
                    "reason": flow.get("reason", ""),
                }
                row["rule_details"] = {
                    "signature_id": alert.get("signature_id", ""),
                    "category": alert.get("category", ""),
                    "severity": alert.get("severity", ""),
                    "action": alert.get("action", ""),
                }
            json_response(self, {"alerts": rows})
        else:
            json_response(self, {"error": "Không tìm thấy endpoint"}, 404)


def main():
    global EVE_PATH, DB_PATH, MODEL_PATH, AI_MODEL, AI_STATUS
    parser = argparse.ArgumentParser(description="Dashboard giám sát cảnh báo Suricata")
    parser.add_argument("--eve", default=str(EVE_PATH), help="Đường dẫn tới eve.json")
    parser.add_argument("--db", default=str(DB_PATH), help="Đường dẫn file SQLite")
    parser.add_argument("--bind", default=BIND, help="Địa chỉ bind; mặc định chỉ truy cập trên máy local")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--model", default=str(MODEL_PATH), help="File mô hình Isolation Forest đã huấn luyện")
    args = parser.parse_args()
    EVE_PATH = Path(args.eve)
    DB_PATH = Path(args.db)
    MODEL_PATH = Path(args.model)
    init_db()
    if load_model:
        try:
            AI_MODEL = load_model(MODEL_PATH)
            AI_STATUS = "Đang hoạt động" if AI_MODEL is not None else f"Chưa có mô hình tại {MODEL_PATH}"
        except Exception as exc:
            AI_STATUS = f"Không nạp được mô hình: {exc}"
            LOG.exception("Không nạp được mô hình AI")
    tailer = EveTailer(EVE_PATH)
    tailer.start()
    server = ThreadingHTTPServer((args.bind, args.port), Handler)
    LOG.warning("Dashboard chạy tại http://%s:%s | nguồn: %s", args.bind, args.port, EVE_PATH)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("Đang dừng dịch vụ")
    finally:
        server.shutdown()
        tailer.stop_event.set()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    main()
