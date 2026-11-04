"""/api/incidents - incident detail, on-demand abstractive summary, PDF report."""
import pandas as pd
from fastapi import APIRouter, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import Response

from db import database as db
from nlp import unit5_summarize_qa as u5
from nlp.unit4_tfidf_ie import build_tfidf, feature_text
from services.pdf_report import build_pdf

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


def _incident_or_404(incident_id):
    inc = db.get_incident(incident_id)
    if inc is None:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return inc


def _srl(a):
    triple = {"actor": a["triple_actor"], "action_head": a["triple_action"]}   # triple_action = verb
    a = dict(a, timestamp=pd.Timestamp(a["timestamp"]))
    return u5.srl_roles(triple, a)


@router.get("/{incident_id}")
def get_incident(incident_id: int, limit: int = 300):
    inc = _incident_or_404(incident_id)
    alerts = db.get_alerts(incident_id=incident_id)
    # SRL roles for the most unusual (highest rarity) distinct alerts
    seen, srl = set(), []
    for a in sorted(alerts, key=lambda x: -(x["rarity_score"] or 0)):
        if a["description"] in seen:
            continue
        seen.add(a["description"])
        srl.append({"alert_id": a["id"], "sentence": a["sentence"], "roles": _srl(a)})
        if len(srl) == 6:
            break
    ents = db.get_entities_for_alerts([a["id"] for a in alerts[:2000]])
    ent_counts = {}
    for e in ents:
        k = (e["text"], e["label"])
        ent_counts[k] = ent_counts.get(k, 0) + 1
    inc["entities"] = [{"text": t, "label": l, "count": c} for (t, l), c in sorted(ent_counts.items(), key=lambda x: -x[1])][:60]
    inc["srl"] = srl
    inc["alerts"] = alerts[:limit]
    inc["n_alerts_shown"] = min(limit, len(alerts))
    return inc


@router.post("/{incident_id}/abstractive")
async def abstractive(incident_id: int):
    """Generate the pretrained-model summary on demand (first call downloads/loads the model)."""
    _incident_or_404(incident_id)
    sentences = [a["sentence"] for a in db.get_alerts(incident_id=incident_id)]
    vec, _ = build_tfidf(list(dict.fromkeys(feature_text(s) for s in sentences)))
    text = " ".join(u5.representative_sentences(sentences, vec, n=12))
    try:
        summary = await run_in_threadpool(u5.abstractive_summary, text)
    except Exception as e:  # noqa: BLE001 - model missing / no internet / out of memory
        raise HTTPException(503, f"AI summarizer unavailable ({type(e).__name__}: {e}). "
                                 "The template and extractive summaries still work.")
    db.set_abstractive(incident_id, summary)
    return {"incident_id": incident_id, "summary_abstractive": summary, "model": u5.ABSTRACTIVE_MODEL}


@router.get("/{incident_id}/pdf")
def pdf(incident_id: int):
    inc = _incident_or_404(incident_id)
    alerts = db.get_alerts(incident_id=incident_id)
    ents = db.get_entities_for_alerts([a["id"] for a in alerts[:2000]])
    data = build_pdf(inc, alerts, ents)
    return Response(data, media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="incident_{incident_id}.pdf"'})
