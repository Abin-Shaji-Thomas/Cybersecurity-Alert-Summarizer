"""/api/lab/process - run ONE pasted alert/sentence through every Learning Unit (viva demo)."""
from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from db import database as db
from nlp import unit1_preprocess_lm as u1
from nlp import unit2_pos_ner_parse as u2
from nlp import unit3_dependency_semantics as u3
from nlp import unit4_tfidf_ie as u4
from nlp import unit5_summarize_qa as u5
from nlp.load_data import flatten_alert, alert_to_sentence, load_alerts
from services.analysis_service import corpus_context

router = APIRouter(prefix="/api/lab", tags=["lab"])
SAMPLE = Path(__file__).resolve().parents[2] / "data" / "sample" / "sample_alerts.json"


class LabInput(BaseModel):
    text: str
    analysis_id: int | None = None
    cky_text: str | None = None


@lru_cache(maxsize=1)
def sample_context():
    """Corpus models from the bundled sample, used when no analysis has been run yet."""
    df = load_alerts(str(SAMPLE))
    sentences = list(df["sentence"])
    lm, stats, token_lists = u1.train_and_evaluate_lm(sentences)
    vec, _ = u4.build_tfidf(list(dict.fromkeys(u4.feature_text(s) for s in sentences)))
    vocab, M = u3.cooccurrence_vectors(token_lists)
    return {"lm": lm, "tfidf": vec, "vocab": vocab, "vectors": u4.ppmi_matrix(M), "name": "bundled sample"}


def _context(analysis_id):
    if analysis_id is None:
        done = [a for a in db.list_analyses() if a["status"] == "done"]
        analysis_id = done[0]["id"] if done else None
    if analysis_id is not None:
        a = db.get_analysis(analysis_id)
        if a is None or a["status"] != "done":
            raise HTTPException(404, f"Analysis {analysis_id} is not available")
        return corpus_context(analysis_id) | {"name": f"analysis #{analysis_id} ({a['filename']})"}
    return sample_context()


def _as_sentence(text):
    """If the user pasted a raw JSON alert, convert it with the same alert-to-sentence step."""
    import json
    import pandas as pd
    t = text.strip()
    if t.startswith("{"):
        try:
            row = flatten_alert(json.loads(t))
            row["timestamp"] = pd.to_datetime(row["timestamp"], utc=True)
            return alert_to_sentence(row), True
        except Exception:  # noqa: BLE001 - not valid alert JSON: treat as plain text
            pass
    return text, False


@router.post("/process")
def process(body: LabInput):
    if not body.text.strip():
        raise HTTPException(400, "Paste an alert or a sentence first")
    if len(body.text) > 5000:
        raise HTTPException(400, "Text too long for the lab (max 5000 characters)")
    ctx = _context(body.analysis_id)
    text, from_json = _as_sentence(body.text)
    doc = u2.get_nlp()(text)
    triple = u3.extract_triple(doc)
    import pandas as pd
    alert_like = {"timestamp": pd.Timestamp.now(tz="UTC"), "dst_port": None, "url": None, "user": None,
                  "host": triple.get("target"), "description": text}
    for e in doc.ents:
        if e.label_ == "PORT":
            alert_like["dst_port"] = e.text
        if e.label_ == "HOST":
            alert_like["host"] = e.text
        if e.label_ == "USER":
            alert_like["user"] = e.text
    return {
        "input": body.text,
        "sentence": text,
        "converted_from_json": from_json,
        "corpus": ctx["name"],
        "unit1": u1.demo(text, ctx["lm"]),
        "unit2": u2.demo(text, body.cky_text),
        "unit3": u3.demo(text, ctx["vocab"], ctx["vectors"]),
        "unit4": u4.demo(text, ctx["tfidf"]),
        "unit5": u5.demo(text, triple, alert_like),
    }
