"""/api/analyses - upload, history, incidents, timeline, entities, insights, Q&A."""
from pathlib import Path

import pandas as pd
from fastapi import APIRouter, BackgroundTasks, File, HTTPException, UploadFile
from pydantic import BaseModel

from db import database as db
from nlp import unit5_summarize_qa as u5
from services.analysis_service import alerts_frame, corpus_context, forget, process_analysis

router = APIRouter(prefix="/api/analyses", tags=["analyses"])

SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample" / "sample_alerts.json"
ALLOWED = {".json", ".jsonl", ".ndjson"}
MAX_MB = 150


def _get_done(analysis_id):
    a = db.get_analysis(analysis_id)
    if a is None:
        raise HTTPException(404, f"Analysis {analysis_id} not found")
    if a["status"] != "done":
        raise HTTPException(409, f"Analysis {analysis_id} is {a['status']}")
    return a


@router.post("")
async def upload(background: BackgroundTasks, file: UploadFile = File(...)):
    ext = Path(file.filename or "").suffix.lower()
    if ext not in ALLOWED:
        raise HTTPException(400, f"Unsupported file type '{ext}'. Upload a Wazuh/Suricata .json or .jsonl file.")
    raw = await file.read()
    if len(raw) > MAX_MB * 1024 * 1024:
        raise HTTPException(413, f"File is {len(raw) / 1e6:.0f} MB; the limit is {MAX_MB} MB.")
    if not raw.strip():
        raise HTTPException(400, "The file is empty.")
    first = raw.lstrip()[:1]
    if first not in (b"[", b"{"):
        raise HTTPException(400, "The file does not look like JSON (expected a JSON array or JSON lines).")
    analysis_id = db.create_analysis(file.filename)
    background.add_task(process_analysis, analysis_id, raw)
    return {"id": analysis_id, "status": "processing"}


@router.post("/sample")
def analyse_sample(background: BackgroundTasks):
    if not SAMPLE.exists():
        raise HTTPException(500, "Sample file data/sample/sample_alerts.json is missing")
    analysis_id = db.create_analysis(SAMPLE.name)
    background.add_task(process_analysis, analysis_id, SAMPLE.read_bytes())
    return {"id": analysis_id, "status": "processing"}


@router.get("")
def list_analyses():
    return db.list_analyses()


@router.get("/{analysis_id}")
def get_analysis(analysis_id: int):
    a = db.get_analysis(analysis_id)
    if a is None:
        raise HTTPException(404, f"Analysis {analysis_id} not found")
    return a


@router.delete("/{analysis_id}")
def delete(analysis_id: int):
    if not db.delete_analysis(analysis_id):
        raise HTTPException(404, f"Analysis {analysis_id} not found")
    forget(analysis_id)
    return {"deleted": analysis_id}


@router.get("/{analysis_id}/incidents")
def incidents(analysis_id: int):
    _get_done(analysis_id)
    return db.list_incidents(analysis_id)


@router.get("/{analysis_id}/insights")
def insights(analysis_id: int):
    a = _get_done(analysis_id)
    return db.get_analysis(analysis_id, with_insights=True)["insights"] | {"analysis": a}


@router.get("/{analysis_id}/timeline")
def timeline(analysis_id: int, limit: int = 400, min_level: int = 0):
    """Events over time: buckets per phase (chart) + compressed ordered event list."""
    _get_done(analysis_id)
    df = alerts_frame(analysis_id)
    span = (df["timestamp"].max() - df["timestamp"].min()).total_seconds()
    freq = "1min" if span <= 3 * 3600 else "15min" if span <= 2 * 86400 else "1h"
    df["bucket"] = df["timestamp"].dt.floor(freq)
    phases = list(df["phase"].value_counts().index)
    pivot = df.pivot_table(index="bucket", columns="phase", values="id", aggfunc="count", fill_value=0)
    lvl = df.groupby("bucket")["level"].max()
    series = [{"time": t.isoformat(), "max_level": int(lvl[t]), **{p: int(row.get(p, 0)) for p in phases}}
              for t, row in pivot.iterrows()]

    # Compress consecutive alerts with the same (description, source, host) into one event
    ev = df[df["level"] >= min_level].sort_values("timestamp")
    events = []
    for a in ev.to_dict("records"):
        actor = a["triple_actor"] or a["src_ip"] or a["user"]
        key = (a["description"], actor, a["host"])
        if events and events[-1]["_key"] == key:
            e = events[-1]
            e["end"] = a["timestamp"].isoformat()
            e["count"] += 1
            e["level"] = max(e["level"], a["level"])
            continue
        events.append({"_key": key, "start": a["timestamp"].isoformat(), "end": a["timestamp"].isoformat(),
                       "count": 1, "description": a["description"], "actor": actor, "target": a["triple_target"] or a["host"],
                       "host": a["host"], "level": a["level"], "phase": a["phase"], "incident_id": a["incident_id"]})
    total_events = len(events)
    for e in events:
        e.pop("_key")
    return {"bucket": freq, "phases": phases, "series": series, "events": events[:limit], "n_events": total_events}


@router.get("/{analysis_id}/entities")
def entities(analysis_id: int, label: str | None = None):
    _get_done(analysis_id)
    ents = db.get_entities_summary(analysis_id, limit=1000)
    labels = sorted({e["label"] for e in ents})
    if label:
        ents = [e for e in ents if e["label"] == label]
    return {"entities": ents, "labels": labels, "relations": db.get_relations(analysis_id)}


class Question(BaseModel):
    question: str


@router.post("/{analysis_id}/ask")
def ask(analysis_id: int, body: Question):
    _get_done(analysis_id)
    q = body.question.strip()
    if not q:
        raise HTTPException(400, "Question is empty")
    if len(q) > 500:
        raise HTTPException(400, "Question is too long (max 500 characters)")
    ctx = corpus_context(analysis_id)
    df = ctx["df"]
    rels = db.get_relations(analysis_id)
    incs = db.list_incidents(analysis_id)
    answer, positions, intent = u5.answer_question(q, df, rels, incs, vec_cache=ctx["qa"])
    support = df.loc[positions, ["id", "timestamp", "sentence", "level", "incident_id", "phase"]].copy()
    support["timestamp"] = support["timestamp"].map(lambda t: t.isoformat())
    db.log_qa(analysis_id, q, answer)
    return {"question": q, "answer": answer, "intent": intent,
            "supporting_alerts": support.to_dict("records")}


@router.get("/{analysis_id}/qa")
def qa_history(analysis_id: int):
    return db.get_qa_logs(analysis_id)
