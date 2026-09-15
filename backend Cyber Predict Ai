import csv
import io
import json
from datetime import datetime, timezone
from typing import Any

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="CyberPredict AI API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STAGES = [
    "Normal Traffic",
    "Port Scanning",
    "Suspicious Login",
    "Privilege Escalation",
    "Data Exfiltration",
]

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
ALLOWED_DATASET_SUFFIXES = {".csv", ".json", ".jsonl"}

def _number(row: dict[str, Any], names: tuple[str, ...]) -> float:
    for name in names:
        for key, value in row.items():
            if key.lower().replace(" ", "_") == name:
                try:
                    return float(value)
                except (TypeError, ValueError):
                    pass
    return 0.0

def _dataset_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    row_count = len(rows)
    failed_logins = sum(_number(row, ("failed_logins", "failed_login_attempts", "login_failures")) for row in rows)
    traffic = sum(_number(row, ("traffic_volume", "bytes", "network_traffic", "traffic")) for row in rows)
    stages_found = [str(row.get("attack_stage", row.get("stage", ""))).lower() for row in rows]
    stage_index = 0
    for index, stage in enumerate(STAGES):
        if any(stage.lower() in value or stage.split()[0].lower() in value for value in stages_found):
            stage_index = max(stage_index, index)
    threat_score = min(99, round((failed_logins * 2 + stage_index * 18 + min(row_count, 100) / 4)))
    confidence = min(98, max(54, 64 + stage_index * 6 + min(row_count, 40) // 4))
    source_keys = ("source_ip", "src_ip", "source", "device_id")
    sources = {str(row.get(key)) for row in rows for key in source_keys if row.get(key)}
    return {
        "row_count": row_count,
        "source_count": len(sources),
        "failed_logins": round(failed_logins),
        "traffic": round(traffic, 2),
        "threat_score": threat_score,
        "confidence": confidence,
        "current_stage": STAGES[stage_index],
        "predicted_next_stage": STAGES[min(stage_index + 1, len(STAGES) - 1)],
        "risk": "CRITICAL" if threat_score >= 75 else "HIGH" if threat_score >= 45 else "ELEVATED",
    }

class ForecastRequest(BaseModel):
    events: list[dict[str, Any]] = []
    current_stage: str = "Suspicious Login"

@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "cyberpredict-api", "mode": "demo"}

@app.post("/api/dataset")
async def upload_dataset(file: UploadFile = File(...)) -> dict[str, Any]:
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_DATASET_SUFFIXES:
        raise HTTPException(status_code=400, detail="Only CSV, JSON, and JSONL datasets are supported.")
    safe_name = Path(file.filename or "dataset" + suffix).name
    DATA_DIR.mkdir(exist_ok=True)
    destination = DATA_DIR / safe_name
    contents = await file.read()
    destination.write_bytes(contents)
    try:
        if suffix == ".csv":
            rows = list(csv.DictReader(io.StringIO(contents.decode("utf-8-sig"))))
        elif suffix == ".jsonl":
            rows = [json.loads(line) for line in contents.decode("utf-8").splitlines() if line.strip()]
        else:
            parsed = json.loads(contents.decode("utf-8"))
            rows = parsed if isinstance(parsed, list) else parsed.get("data", [parsed])
        rows = [row for row in rows if isinstance(row, dict)]
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as error:
        raise HTTPException(status_code=400, detail=f"Could not parse dataset: {error}") from error
    return {"filename": safe_name, "path": f"data/{safe_name}", "summary": _dataset_summary(rows), "simulated": True}

@app.post("/api/forecast")
def forecast(payload: ForecastRequest) -> dict[str, Any]:
    try:
        current_index = STAGES.index(payload.current_stage)
    except ValueError:
        current_index = 2
    next_index = min(current_index + 1, len(STAGES) - 1)
    confidence = min(98, 78 + current_index * 5)
    return {
        "current_stage": STAGES[current_index],
        "predicted_next_stage": STAGES[next_index],
        "risk": "CRITICAL" if current_index >= 3 else "HIGH",
        "confidence": confidence,
        "simulated": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/api/simulate")
def simulate() -> dict[str, Any]:
    return {
        "stages": STAGES,
        "interval_ms": 1500,
        "simulated": True,
        "message": "Demo attack sequence generated. No trained ML model was queried.",
    }
