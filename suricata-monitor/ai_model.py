"""Isolation Forest helpers for defensive flow-level anomaly detection."""
from __future__ import annotations

import json
import math
from datetime import datetime
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

APP_PROTOCOLS = {
    "": 0, "unknown": 0, "http": 1, "dns": 2, "tls": 3,
    "ssh": 4, "smtp": 5, "ftp": 6, "dhcp": 7, "smb": 8,
}
PROTOCOLS = {"": 0, "TCP": 6, "UDP": 17, "ICMP": 1, "ICMPv6": 58}


def _number(value, default=0.0):
    try:
        result = float(value)
        return result if math.isfinite(result) and result >= 0 else default
    except (TypeError, ValueError):
        return default


def _duration(event, flow):
    age = flow.get("age")
    if age is not None:
        return _number(age)
    try:
        start = datetime.fromisoformat(str(flow["start"]).replace("Z", "+00:00"))
        end = datetime.fromisoformat(str(flow["end"]).replace("Z", "+00:00"))
        return max(0.0, (end - start).total_seconds())
    except (KeyError, TypeError, ValueError):
        return 0.0


def flow_features(event):
    """Return a fixed numeric feature vector from one Suricata flow event."""
    flow = event.get("flow") if isinstance(event.get("flow"), dict) else {}
    proto = str(event.get("proto") or "").upper()
    app_proto = str(event.get("app_proto") or "").lower()
    return np.asarray([[
        math.log1p(_number(flow.get("bytes_toserver"))),
        math.log1p(_number(flow.get("bytes_toclient"))),
        math.log1p(_number(flow.get("pkts_toserver"))),
        math.log1p(_number(flow.get("pkts_toclient"))),
        math.log1p(_duration(event, flow)),
        _number(event.get("src_port")),
        _number(event.get("dest_port")),
        float(PROTOCOLS.get(proto, 0)),
        float(APP_PROTOCOLS.get(app_proto, 0)),
    ]], dtype=np.float64)


def read_flow_features(eve_path):
    rows = []
    with Path(eve_path).open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict) and event.get("event_type") == "flow":
                rows.append(flow_features(event)[0])
    return np.asarray(rows, dtype=np.float64)


def train(eve_path, model_path, contamination=0.02):
    rows = read_flow_features(eve_path)
    if len(rows) < 100:
        raise ValueError(f"Cần ít nhất 100 flow event để tạo baseline; hiện có {len(rows)}.")
    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(rows)
    target = Path(model_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, target)
    return len(rows), target


def load_model(path):
    target = Path(path)
    if not target.is_file():
        return None
    return joblib.load(target)


def score_flow(model, event):
    """Return (is_anomalous, score), where lower Isolation Forest scores are unusual."""
    features = flow_features(event)
    prediction = int(model.predict(features)[0])
    score = float(model.decision_function(features)[0])
    return prediction == -1, score
